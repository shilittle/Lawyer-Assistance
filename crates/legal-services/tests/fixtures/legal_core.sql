BEGIN;

INSERT INTO issuing_authorities (id, name, authority_type, country_region)
VALUES ('npc', '全国人民代表大会', 'legislature', 'CN');

INSERT INTO law_documents (
  id, title, title_pinyin, document_type, authority_id, jurisdiction,
  effectiveness_level, status, promulgated_on, source_url, summary
) VALUES
  ('civil-code', '中华人民共和国民法典', 'min fa dian', 'law', 'npc', 'CN',
   'national_law', 'in_force', '2020-05-28', 'https://example.invalid/civil-code',
   '仅用于 legal-services 自动化测试的最小法律数据。'),
  ('old-contract-law', '中华人民共和国合同法', 'he tong fa', 'law', 'npc', 'CN',
   'national_law', 'repealed', '1999-03-15', 'https://example.invalid/contract-law',
   '仅用于法律关系测试的失效法律。');

INSERT INTO law_versions (
  id, document_id, version_label, status, effective_from, effective_to,
  published_on, source_reference
) VALUES
  ('civil-code-v1', 'civil-code', '2021年施行版本', 'in_force', '2021-01-01', NULL,
   '2020-05-28', 'test fixture'),
  ('contract-law-v1', 'old-contract-law', '1999年施行版本', 'repealed',
   '1999-10-01', '2020-12-31', '1999-03-15', 'test fixture');

INSERT INTO law_articles (
  id, document_id, version_id, article_number, article_order, title, content, updated_on
) VALUES
  ('civil-code-465', 'civil-code', 'civil-code-v1', '第四百六十五条', 465,
   '依法成立合同的效力', '依法成立的合同，受法律保护。', '2026-07-17'),
  ('contract-law-107', 'old-contract-law', 'contract-law-v1', '第一百零七条', 107,
   '违约责任', '一方不履行合同义务的，应当承担违约责任。', '2020-12-31');

INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label)
VALUES
  ('citation-465', 'civil-code-465',
   'law:civil-code:civil-code-v1:art:465', '《中华人民共和国民法典》第四百六十五条'),
  ('citation-contract-107', 'contract-law-107',
   'law:old-contract-law:contract-law-v1:art:107', '《中华人民共和国合同法》第一百零七条');

INSERT INTO law_aliases (id, document_id, alias, normalized_alias)
VALUES ('alias-civil-code', 'civil-code', '民法典', '民法典');

INSERT INTO law_relations (
  id, from_document_id, to_document_id, relation_type, description, source_reference
) VALUES ('relation-replaces', 'civil-code', 'old-contract-law', 'replaces',
          '民法典施行后合同法废止。', 'test fixture');

INSERT INTO law_articles_fts (
  article_id, document_id, version_id, document_title, article_number, article_title, content
) VALUES
  ('civil-code-465', 'civil-code', 'civil-code-v1', '中华人民共和国民法典',
   '第四百六十五条', '依法成立合同的效力', '依法成立的合同，受法律保护。'),
  ('contract-law-107', 'old-contract-law', 'contract-law-v1', '中华人民共和国合同法',
   '第一百零七条', '违约责任', '一方不履行合同义务的，应当承担违约责任。');

INSERT INTO database_metadata (key, value, updated_at)
VALUES ('dataset_version', 'legal-services-fixture-v1', '2026-07-17T00:00:00Z');

COMMIT;
