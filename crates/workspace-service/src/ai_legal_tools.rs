use crate::*;

impl AiRunRequest {
    pub(crate) fn validate_search_options(&self) -> Result<()> {
        if !matches!(
            self.match_mode.as_deref().unwrap_or("all"),
            "all" | "any" | "phrase"
        ) {
            return Err(Error::new("invalid_search_request"));
        }
        let scope = self.search_version_scope();
        if !matches!(scope, "current" | "as_of" | "all")
            || (scope == "as_of") != self.case_date.is_some()
            || self
                .case_date
                .as_deref()
                .is_some_and(|date| !domain::date::is_iso_calendar_date(date))
            || self
                .version_status
                .as_deref()
                .is_some_and(|s| s.len() > 128 || s.contains('\0'))
        {
            return Err(Error::new("invalid_search_request"));
        }
        Ok(())
    }

    pub(crate) fn search_version_scope(&self) -> &str {
        self.version_scope
            .as_deref()
            .unwrap_or(if self.case_date.is_some() {
                "as_of"
            } else {
                "current"
            })
    }

    fn tool_search_request(&self, args: &Value, offset: u32) -> Result<Value> {
        self.validate_search_options()?;
        // Model arguments cannot change the visible, user-selected date/scope.
        for (key, selected) in [
            ("case_date", self.case_date.as_deref()),
            (
                "match_mode",
                Some(self.match_mode.as_deref().unwrap_or("all")),
            ),
            ("version_scope", Some(self.search_version_scope())),
            ("version_status", self.version_status.as_deref()),
        ] {
            if let Some(proposed) = args.get(key).filter(|v| !v.is_null()) {
                if proposed.as_str() != selected {
                    return Err(Error::new("search_scope_conflict"));
                }
            }
        }
        Ok(json!({
            "schemaVersion":1,"query":required(args,"query")?,"view":"flat",
            "documentId":args["document_id"],"caseDate":self.case_date,
            "matchMode":self.match_mode.as_deref().unwrap_or("all"),
            "versionScope":self.search_version_scope(),"versionStatus":self.version_status,
            "limit":12,"offset":offset
        }))
    }
}

fn required(args: &Value, key: &str) -> Result<String> {
    args[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() < 16000)
        .map(str::to_owned)
        .ok_or_else(|| Error::new("invalid_tool_arguments"))
}

fn tool_error(error: legal_services::ServiceError) -> Error {
    Error::new(match error.code.as_str() {
        "invalid_request" => "invalid_tool_arguments",
        "not_found" => "not_found",
        "cancelled" | "request_cancelled" => "cancelled",
        "capacity_exceeded" => "capacity_exceeded",
        _ => "legal_tool_unavailable",
    })
}

struct CancelSearchOnDrop(legal_services::SearchCancellation);
impl Drop for CancelSearchOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl Workspace {
    pub(crate) async fn execute_legal_tool(
        &self,
        name: &str,
        args: Value,
        options: &AiRunRequest,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let permit = self
            .acquire_admission(AdmissionClass::Search, cancel)
            .await?;
        let legal = self.legal.clone();
        let name = name.to_owned();
        let offset = args["offset"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32;
        let search = if name == "legal_search" {
            Some(options.tool_search_request(&args, offset)?)
        } else {
            None
        };
        let worker_token = cancel.clone();
        let query_cancel = legal_services::SearchCancellation::new();
        let _cancel_query = CancelSearchOnDrop(query_cancel.clone());
        let worker_query_cancel = query_cancel.clone();
        let case_date = options.case_date.clone();
        let version_scope = serde_json::from_value::<legal_services::LegalVersionScope>(json!(
            options.search_version_scope()
        ))?;
        let mut worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if worker_token.is_cancelled() {
                return Err(Error::new("cancelled"));
            }
            match name.as_str() {
                "legal_search" => {
                    let request = serde_json::from_value::<legal_services::LegalPagedSearchRequest>(
                        search.expect("search request prepared"),
                    )?;
                    Ok(serde_json::to_value(
                        legal
                            .legal_search_page_cancellable(request, &worker_query_cancel)
                            .map_err(tool_error)?,
                    )?)
                }
                "legal_get_article" => Ok(serde_json::to_value(
                    legal
                        .legal_get_article_scoped_cancellable(
                            legal_services::LegalGetArticleScopedRequest {
                                schema_version: 1,
                                article_id: required(&args, "article_id")?,
                                case_date,
                                version_scope: Some(version_scope),
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                "legal_get_versions" => Ok(serde_json::to_value(
                    legal
                        .legal_get_versions_cancellable(
                            legal_services::LegalGetVersionsRequest {
                                schema_version: 1,
                                document_id: required(&args, "document_id")?,
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                "legal_version_articles" => Ok(serde_json::to_value(
                    legal
                        .legal_version_articles_scoped_cancellable(
                            legal_services::LegalVersionArticlesScopedRequest {
                                schema_version: 1,
                                version_id: required(&args, "version_id")?,
                                case_date,
                                version_scope: Some(version_scope),
                                limit: Some(12),
                                offset: Some(offset),
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                "legal_get_relations" => Ok(serde_json::to_value(
                    legal
                        .legal_get_relations_cancellable(
                            legal_services::LegalGetRelationsRequest {
                                schema_version: 1,
                                document_id: required(&args, "document_id")?,
                                direction: None,
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                "legal_search_cases" => Ok(serde_json::to_value(
                    legal
                        .judicial_case_search_cancellable(
                            legal_services::JudicialCaseSearchRequest {
                                schema_version: 1,
                                query: required(&args, "query")?,
                                case_type: args["case_type"].as_str().map(str::to_owned),
                                limit: Some(8),
                                offset: Some(offset),
                                include_withdrawn: Some(false),
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                "legal_get_case" => Ok(serde_json::to_value(
                    legal
                        .judicial_case_get_cancellable(
                            legal_services::JudicialCaseGetRequest {
                                schema_version: 1,
                                case_id: required(&args, "case_id")?,
                            },
                            &worker_query_cancel,
                        )
                        .map_err(tool_error)?,
                )?),
                _ => Err(Error::new("tool_not_allowed")),
            }
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                query_cancel.cancel();
                // Keep capacity until the blocking worker actually returns.
                let _ = worker.await;
                Err(Error::new("cancelled"))
            }
            result = &mut worker => result.map_err(|_| Error::new("legal_tool_failed"))?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_tools_cannot_override_visible_search_scope() {
        let request = AiRunRequest {
            match_mode: Some("phrase".into()),
            version_scope: Some("as_of".into()),
            case_date: Some("2019-12-31".into()),
            ..Default::default()
        };
        let prepared = request
            .tool_search_request(&json!({"query":"合同 解除"}), 0)
            .unwrap();
        assert_eq!(prepared["matchMode"], "phrase");
        assert_eq!(prepared["caseDate"], "2019-12-31");
        assert_eq!(
            request
                .tool_search_request(&json!({"query":"合同","case_date":"2026-09-10"}), 0)
                .unwrap_err()
                .code,
            "search_scope_conflict"
        );
        assert_eq!(
            AiRunRequest::default()
                .tool_search_request(&json!({"query":"合同","case_date":"2020-01-01"}), 0)
                .unwrap_err()
                .code,
            "search_scope_conflict"
        );
    }

    #[test]
    fn dates_and_scope_are_rejected_before_model_dispatch() {
        for request in [
            AiRunRequest {
                case_date: Some("2026-02-30".into()),
                ..Default::default()
            },
            AiRunRequest {
                version_scope: Some("as_of".into()),
                ..Default::default()
            },
            AiRunRequest {
                version_scope: Some("all".into()),
                case_date: Some("2026-09-10".into()),
                ..Default::default()
            },
            AiRunRequest {
                match_mode: Some("approximate".into()),
                ..Default::default()
            },
        ] {
            assert_eq!(
                request.validate_search_options().unwrap_err().code,
                "invalid_search_request"
            );
        }
        AiRunRequest::default().validate_search_options().unwrap();
    }
}
