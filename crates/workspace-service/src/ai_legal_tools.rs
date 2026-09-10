use crate::*;
impl Workspace {
    pub(crate) async fn execute_legal_tool(
        &self,
        name: &str,
        args: Value,
        case_date: Option<String>,
    ) -> Result<Value> {
        let legal = self.legal.clone();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move||{
            let required=|key:&str|args[key].as_str().filter(|s|!s.is_empty()&&s.len()<16000).map(str::to_owned).ok_or_else(||Error::new("invalid_tool_arguments"));
            let offset=args["offset"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32;
            let err=|_:legal_services::ServiceError|Error::new("legal_tool_unavailable");
            match name.as_str(){
                "legal_search"=>{
                    let r:legal_services::LegalPagedSearchRequest=serde_json::from_value(json!({"schemaVersion":1,"query":required("query")?,"view":"flat","documentId":args["document_id"],"caseDate":args["case_date"].as_str().map(str::to_owned).or(case_date),"limit":12,"offset":offset}))?;
                    Ok(serde_json::to_value(legal.legal_search_page(r).map_err(err)?)?)
                },
                "legal_get_article"=>Ok(serde_json::to_value(legal.legal_get_article(legal_services::LegalGetArticleRequest{schema_version:1,article_id:required("article_id")?}).map_err(err)?)?),
                "legal_get_versions"=>Ok(serde_json::to_value(legal.legal_get_versions(legal_services::LegalGetVersionsRequest{schema_version:1,document_id:required("document_id")?}).map_err(err)?)?),
                "legal_version_articles"=>Ok(serde_json::to_value(legal.legal_version_articles(legal_services::LegalVersionArticlesRequest{schema_version:1,version_id:required("version_id")?,limit:Some(12),offset:Some(offset)}).map_err(err)?)?),
                "legal_get_relations"=>Ok(serde_json::to_value(legal.legal_get_relations(legal_services::LegalGetRelationsRequest{schema_version:1,document_id:required("document_id")?,direction:None}).map_err(err)?)?),
                "legal_search_cases"=>Ok(serde_json::to_value(legal.judicial_case_search(legal_services::JudicialCaseSearchRequest{schema_version:1,query:required("query")?,case_type:args["case_type"].as_str().map(str::to_owned),limit:Some(8),offset:Some(offset),include_withdrawn:Some(false)}).map_err(err)?)?),
                "legal_get_case"=>Ok(serde_json::to_value(legal.judicial_case_get(legal_services::JudicialCaseGetRequest{schema_version:1,case_id:required("case_id")?}).map_err(err)?)?),
                _=>Err(Error::new("tool_not_allowed"))
            }
        }).await.map_err(|_|Error::new("legal_tool_failed"))?
    }
}
