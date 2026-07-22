use crate::{
    process_pdf_with_cancel, InputTransformTrace, LocalMineruConfig, OcrMode, ProcessedDocument,
    ProcessingError, ProcessingLimits, RasterImageFormat, RASTER_TO_PDF_TRANSFORM_VERSION,
};
use image::{
    DynamicImage, GenericImageView, ImageDecoder, ImageError, ImageFormat, ImageReader, Limits,
};
use lopdf::{
    content::{Content, Operation},
    dictionary, Document, Object, Stream,
};
use sha2::{Digest, Sha256};
use std::{
    io::Cursor,
    sync::{atomic::AtomicBool, Arc},
};

pub const MAX_RASTER_DIMENSION: u32 = 12_000;
pub const MAX_RASTER_PIXELS: u64 = 24_000_000;
pub const MAX_RASTER_DECODE_BYTES: u64 = 192 * 1024 * 1024;
pub const MAX_DERIVED_PDF_BYTES: usize = 96 * 1024 * 1024;
const RASTER_DPI: f32 = 300.0;

pub fn process_raster_image(
    bytes: &[u8],
    format: RasterImageFormat,
    ocr_mode: OcrMode,
    mineru: Option<&LocalMineruConfig>,
    limits: ProcessingLimits,
) -> Result<ProcessedDocument, ProcessingError> {
    process_raster_image_with_cancel(bytes, format, ocr_mode, mineru, limits, None)
}

pub fn process_raster_image_with_cancel(
    bytes: &[u8],
    format: RasterImageFormat,
    ocr_mode: OcrMode,
    mineru: Option<&LocalMineruConfig>,
    limits: ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
) -> Result<ProcessedDocument, ProcessingError> {
    if bytes.is_empty() {
        return Err(ProcessingError::InvalidRasterImage);
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(ProcessingError::InputTooLarge);
    }

    let source_sha256 = sha256_hex(bytes);
    let decoded = decode_bounded_image(bytes, format)?;
    let pixel_width = decoded.width();
    let pixel_height = decoded.height();
    let pdf_bytes = deterministic_image_pdf(decoded, &source_sha256)?;
    if pdf_bytes.len() > MAX_DERIVED_PDF_BYTES {
        return Err(ProcessingError::RasterImageDimensionsExceeded);
    }
    let processing_sha256 = sha256_hex(&pdf_bytes);

    let mut derived_limits = limits;
    derived_limits.max_input_bytes = derived_limits.max_input_bytes.max(pdf_bytes.len());
    let mut processed =
        process_pdf_with_cancel(&pdf_bytes, ocr_mode, mineru, derived_limits, cancelled)?;
    processed.source_sha256 = source_sha256.clone();
    processed.media_type = format.media_type().to_owned();
    processed.processing_version = format!(
        "{}+{}",
        processed.processing_version, RASTER_TO_PDF_TRANSFORM_VERSION
    );
    processed.input_transform = Some(InputTransformTrace {
        schema_version: 1,
        transform_version: RASTER_TO_PDF_TRANSFORM_VERSION.to_owned(),
        source_media_type: format.media_type().to_owned(),
        source_sha256,
        processing_media_type: "application/pdf".to_owned(),
        processing_sha256,
        pixel_width,
        pixel_height,
    });
    Ok(processed)
}

fn decode_bounded_image(
    bytes: &[u8],
    expected_format: RasterImageFormat,
) -> Result<DynamicImage, ProcessingError> {
    let detected = image::guess_format(bytes).map_err(|_| ProcessingError::InvalidRasterImage)?;
    let expected = match expected_format {
        RasterImageFormat::Png => ImageFormat::Png,
        RasterImageFormat::Jpeg => ImageFormat::Jpeg,
    };
    if detected != expected {
        return Err(ProcessingError::InvalidRasterImage);
    }

    let mut reader = ImageReader::with_format(Cursor::new(bytes), expected);
    let mut decode_limits = Limits::default();
    decode_limits.max_image_width = Some(MAX_RASTER_DIMENSION);
    decode_limits.max_image_height = Some(MAX_RASTER_DIMENSION);
    decode_limits.max_alloc = Some(MAX_RASTER_DECODE_BYTES);
    reader.limits(decode_limits);
    let mut decoder = reader.into_decoder().map_err(map_image_error)?;
    let (encoded_width, encoded_height) = decoder.dimensions();
    validate_dimensions(encoded_width, encoded_height)?;
    let orientation = decoder.orientation().map_err(map_image_error)?;
    let mut image = DynamicImage::from_decoder(decoder).map_err(map_image_error)?;
    image.apply_orientation(orientation);
    validate_dimensions(image.width(), image.height())?;
    Ok(image)
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), ProcessingError> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ProcessingError::RasterImageDimensionsExceeded)?;
    if width == 0
        || height == 0
        || width > MAX_RASTER_DIMENSION
        || height > MAX_RASTER_DIMENSION
        || pixels > MAX_RASTER_PIXELS
    {
        return Err(ProcessingError::RasterImageDimensionsExceeded);
    }
    Ok(())
}

fn map_image_error(error: ImageError) -> ProcessingError {
    match error {
        ImageError::Limits(_) => ProcessingError::RasterImageDimensionsExceeded,
        _ => ProcessingError::InvalidRasterImage,
    }
}

fn deterministic_image_pdf(
    image: DynamicImage,
    source_sha256: &str,
) -> Result<Vec<u8>, ProcessingError> {
    let (width, height) = image.dimensions();
    validate_dimensions(width, height)?;
    let rgba = image.into_rgba8();
    let pixel_count = usize::try_from(u64::from(width) * u64::from(height))
        .map_err(|_| ProcessingError::RasterImageDimensionsExceeded)?;
    let rgb_capacity = pixel_count
        .checked_mul(3)
        .ok_or(ProcessingError::RasterImageDimensionsExceeded)?;
    let mut rgb = Vec::with_capacity(rgb_capacity);
    for pixel in rgba.pixels() {
        let alpha = u16::from(pixel[3]);
        for channel in &pixel.0[..3] {
            let composited = (u16::from(*channel) * alpha + 255 * (255 - alpha) + 127) / 255;
            rgb.push(u8::try_from(composited).unwrap_or(255));
        }
    }
    if rgb.len() != rgb_capacity {
        return Err(ProcessingError::InvalidRasterImage);
    }

    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut image_stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => i64::from(width),
            "Height" => i64::from(height),
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
            "Interpolate" => false,
        },
        rgb,
    );
    image_stream
        .compress()
        .map_err(|_| ProcessingError::InvalidRasterImage)?;
    let image_id = document.add_object(image_stream);
    let resources_id = document.add_object(dictionary! {
        "XObject" => dictionary! { "Image0" => image_id },
    });

    let points_per_pixel = 72.0 / RASTER_DPI;
    let page_width = width as f32 * points_per_pixel;
    let page_height = height as f32 * points_per_pixel;
    let content = Content {
        operations: vec![
            Operation::new("q", vec![]),
            Operation::new(
                "cm",
                vec![
                    Object::Real(page_width),
                    0.into(),
                    0.into(),
                    Object::Real(page_height),
                    0.into(),
                    0.into(),
                ],
            ),
            Operation::new("Do", vec![Object::Name(b"Image0".to_vec())]),
            Operation::new("Q", vec![]),
        ],
    }
    .encode()
    .map_err(|_| ProcessingError::InvalidRasterImage)?;
    let content_id = document.add_object(Stream::new(dictionary! {}, content));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => resources_id,
        "MediaBox" => vec![
            0.into(),
            0.into(),
            Object::Real(page_width),
            Object::Real(page_height),
        ],
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(source_sha256),
            Object::string_literal(source_sha256),
        ]),
    );

    let mut output = Vec::new();
    document
        .save_to(&mut output)
        .map_err(|_| ProcessingError::InvalidRasterImage)?;
    if !output.starts_with(b"%PDF-") || output.len() > MAX_DERIVED_PDF_BYTES {
        return Err(ProcessingError::RasterImageDimensionsExceeded);
    }
    Ok(output)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{
        codecs::{jpeg::JpegEncoder, png::PngEncoder},
        ExtendedColorType, ImageEncoder,
    };

    fn rgba_png(width: u32, height: u32) -> Vec<u8> {
        let mut pixels = Vec::new();
        for index in 0..(u64::from(width) * u64::from(height)) {
            let value = u8::try_from(index % 251).unwrap();
            pixels.extend_from_slice(&[value, 255 - value, 127, 200]);
        }
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&pixels, width, height, ExtendedColorType::Rgba8)
            .unwrap();
        bytes
    }

    fn rgb_jpeg(width: u32, height: u32) -> Vec<u8> {
        let mut pixels = Vec::new();
        for index in 0..(u64::from(width) * u64::from(height)) {
            let value = u8::try_from(index % 251).unwrap();
            pixels.extend_from_slice(&[value, 255 - value, 127]);
        }
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 90)
            .write_image(&pixels, width, height, ExtendedColorType::Rgb8)
            .unwrap();
        bytes
    }

    #[test]
    fn png_wrapper_is_deterministic_and_contains_visual_page() {
        let source = rgba_png(12, 8);
        let first = decode_bounded_image(&source, RasterImageFormat::Png).unwrap();
        let second = decode_bounded_image(&source, RasterImageFormat::Png).unwrap();
        let hash = sha256_hex(&source);
        let first_pdf = deterministic_image_pdf(first, &hash).unwrap();
        let second_pdf = deterministic_image_pdf(second, &hash).unwrap();
        assert_eq!(first_pdf, second_pdf);

        let assessment =
            crate::assess_pdf_text_layer(&first_pdf, &ProcessingLimits::default()).unwrap();
        assert_eq!(assessment.len(), 1);
        assert_eq!(
            assessment[0].decision,
            crate::PageExtractionDecision::LocalOcrRequired
        );
        assert!(assessment[0]
            .reason_codes
            .contains(&crate::QualityReasonCode::VisualContentPresent));
    }

    #[test]
    fn jpeg_is_fully_decoded_before_deterministic_wrapping() {
        let source = rgb_jpeg(9, 7);
        let decoded = decode_bounded_image(&source, RasterImageFormat::Jpeg).unwrap();
        assert_eq!(decoded.dimensions(), (9, 7));
        let pdf = deterministic_image_pdf(decoded, &sha256_hex(&source)).unwrap();
        let assessment = crate::assess_pdf_text_layer(&pdf, &ProcessingLimits::default()).unwrap();
        assert_eq!(
            assessment[0].decision,
            crate::PageExtractionDecision::LocalOcrRequired
        );
    }

    #[test]
    fn raster_image_never_silently_falls_back_when_ocr_is_off() {
        let source = rgba_png(4, 3);
        let error = process_raster_image(
            &source,
            RasterImageFormat::Png,
            OcrMode::Off,
            None,
            ProcessingLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error, ProcessingError::OcrDisabled);
    }

    #[test]
    fn rejects_extension_format_mismatch_and_corruption() {
        let source = rgba_png(2, 2);
        assert_eq!(
            decode_bounded_image(&source, RasterImageFormat::Jpeg).unwrap_err(),
            ProcessingError::InvalidRasterImage
        );
        assert_eq!(
            decode_bounded_image(b"not-an-image", RasterImageFormat::Png).unwrap_err(),
            ProcessingError::InvalidRasterImage
        );
    }

    #[test]
    fn rejects_pixel_count_beyond_bound() {
        assert_eq!(
            validate_dimensions(6_000, 6_000).unwrap_err(),
            ProcessingError::RasterImageDimensionsExceeded
        );
    }
}
