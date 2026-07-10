BEGIN;

INSERT INTO issuing_authorities (id, name, authority_type, country_region) VALUES
  ('npc', '全国人民代表大会', 'legislature', 'CN'),
  ('npcsc', '全国人民代表大会常务委员会', 'legislature', 'CN');

INSERT INTO law_documents (
  id,
  title,
  title_pinyin,
  document_type,
  authority_id,
  jurisdiction,
  effectiveness_level,
  status,
  promulgated_on,
  source_url,
  summary
) VALUES
  (
    'cn-civil-code',
    '中华人民共和国民法典',
    'zhong hua ren min gong he guo min fa dian',
    'law',
    'npc',
    'CN',
    'national_law',
    'in_force',
    '2020-05-28',
    'https://flk.npc.gov.cn/',
    '检索测试夹具：民事基本法律，用于验证合同编条文检索。'
  ),
  (
    'cn-labor-contract-law',
    '中华人民共和国劳动合同法',
    'zhong hua ren min gong he guo lao dong he tong fa',
    'law',
    'npcsc',
    'CN',
    'national_law',
    'in_force',
    '2007-06-29',
    'https://flk.npc.gov.cn/',
    '检索测试夹具：劳动合同领域法律，用于验证劳动关系条文检索。'
  ),
  (
    'cn-contract-law-1999',
    '中华人民共和国合同法',
    'zhong hua ren min gong he guo he tong fa',
    'law',
    'npc',
    'CN',
    'national_law',
    'repealed',
    '1999-03-15',
    'https://flk.npc.gov.cn/',
    '检索测试夹具：已失效合同法，用于验证按案件日期匹配历史版本。'
  );

INSERT INTO law_versions (
  id,
  document_id,
  version_label,
  status,
  effective_from,
  effective_to,
  published_on,
  source_reference
) VALUES
  (
    'cn-civil-code-20210101',
    'cn-civil-code',
    '2021年1月1日施行版本',
    'in_force',
    '2021-01-01',
    NULL,
    '2020-05-28',
    '国家法律法规数据库'
  ),
  (
    'cn-labor-contract-law-20130701',
    'cn-labor-contract-law',
    '2013年7月1日施行修正版本',
    'in_force',
    '2013-07-01',
    NULL,
    '2012-12-28',
    '国家法律法规数据库'
  ),
  (
    'cn-contract-law-19991001',
    'cn-contract-law-1999',
    '1999年10月1日施行版本',
    'repealed',
    '1999-10-01',
    '2020-12-31',
    '1999-03-15',
    '国家法律法规数据库'
  );

INSERT INTO law_articles (
  id,
  document_id,
  version_id,
  article_number,
  article_order,
  title,
  content,
  updated_on
) VALUES
  (
    'cn-civil-code-20210101-465',
    'cn-civil-code',
    'cn-civil-code-20210101',
    '第四百六十五条',
    465,
    '依法成立合同的效力',
    '依法成立的合同，受法律保护。依法成立的合同，仅对当事人具有法律约束力，但是法律另有规定的除外。',
    '2026-07-02'
  ),
  (
    'cn-civil-code-20210101-509',
    'cn-civil-code',
    'cn-civil-code-20210101',
    '第五百零九条',
    509,
    '合同履行原则',
    '当事人应当按照约定全面履行自己的义务。当事人应当遵循诚信原则，根据合同的性质、目的和交易习惯履行通知、协助、保密等义务。',
    '2026-07-02'
  ),
  (
    'cn-civil-code-20210101-577',
    'cn-civil-code',
    'cn-civil-code-20210101',
    '第五百七十七条',
    577,
    '违约责任',
    '当事人一方不履行合同义务或者履行合同义务不符合约定的，应当承担继续履行、采取补救措施或者赔偿损失等违约责任。',
    '2026-07-02'
  ),
  (
    'cn-labor-contract-law-20130701-10',
    'cn-labor-contract-law',
    'cn-labor-contract-law-20130701',
    '第十条',
    10,
    '订立书面劳动合同',
    '建立劳动关系，应当订立书面劳动合同。已建立劳动关系，未同时订立书面劳动合同的，应当自用工之日起一个月内订立书面劳动合同。',
    '2026-07-02'
  ),
  (
    'cn-labor-contract-law-20130701-36',
    'cn-labor-contract-law',
    'cn-labor-contract-law-20130701',
    '第三十六条',
    36,
    '协商解除劳动合同',
    '用人单位与劳动者协商一致，可以解除劳动合同。',
    '2026-07-02'
  ),
  (
    'cn-labor-contract-law-20130701-82',
    'cn-labor-contract-law',
    'cn-labor-contract-law-20130701',
    '第八十二条',
    82,
    '未订立书面劳动合同的法律责任',
    '用人单位自用工之日起超过一个月不满一年未与劳动者订立书面劳动合同的，应当向劳动者每月支付二倍的工资。',
    '2026-07-02'
  ),
  (
    'cn-contract-law-19991001-107',
    'cn-contract-law-1999',
    'cn-contract-law-19991001',
    '第一百零七条',
    107,
    '违约责任',
    '当事人一方不履行合同义务或者履行合同义务不符合约定的，应当承担继续履行、采取补救措施或者赔偿损失等违约责任。',
    '2026-07-02'
  );

INSERT INTO law_relations (
  id,
  from_document_id,
  to_document_id,
  relation_type,
  description,
  source_reference
) VALUES
  (
    'rel-civil-code-replaces-contract-law',
    'cn-civil-code',
    'cn-contract-law-1999',
    'replaces',
    '民法典施行后，合同法同时废止。',
    '国家法律法规数据库'
  ),
  (
    'rel-contract-law-replaced-by-civil-code',
    'cn-contract-law-1999',
    'cn-civil-code',
    'replaced_by',
    '合同法已由民法典相关编章承接。',
    '国家法律法规数据库'
  );

INSERT INTO law_aliases (id, document_id, alias, normalized_alias) VALUES
  ('alias-civil-code-1', 'cn-civil-code', '民法典', '民法典'),
  ('alias-civil-code-2', 'cn-civil-code', '民法', '民法'),
  ('alias-labor-contract-1', 'cn-labor-contract-law', '劳动合同法', '劳动合同法'),
  ('alias-labor-contract-2', 'cn-labor-contract-law', '劳动合同', '劳动合同'),
  ('alias-contract-law-1', 'cn-contract-law-1999', '合同法', '合同法');

INSERT INTO legal_topics (id, name, parent_topic_id) VALUES
  ('topic-contract', '合同', NULL),
  ('topic-labor', '劳动关系', NULL),
  ('topic-liability', '法律责任', NULL);

INSERT INTO article_topics (article_id, topic_id) VALUES
  ('cn-civil-code-20210101-465', 'topic-contract'),
  ('cn-civil-code-20210101-509', 'topic-contract'),
  ('cn-civil-code-20210101-577', 'topic-contract'),
  ('cn-civil-code-20210101-577', 'topic-liability'),
  ('cn-labor-contract-law-20130701-10', 'topic-labor'),
  ('cn-labor-contract-law-20130701-36', 'topic-labor'),
  ('cn-labor-contract-law-20130701-82', 'topic-labor'),
  ('cn-labor-contract-law-20130701-82', 'topic-liability'),
  ('cn-contract-law-19991001-107', 'topic-contract'),
  ('cn-contract-law-19991001-107', 'topic-liability');

INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label) VALUES
  (
    'cite-civil-code-465',
    'cn-civil-code-20210101-465',
    'law:cn-civil-code:cn-civil-code-20210101:art:465',
    '《中华人民共和国民法典》第四百六十五条'
  ),
  (
    'cite-civil-code-509',
    'cn-civil-code-20210101-509',
    'law:cn-civil-code:cn-civil-code-20210101:art:509',
    '《中华人民共和国民法典》第五百零九条'
  ),
  (
    'cite-civil-code-577',
    'cn-civil-code-20210101-577',
    'law:cn-civil-code:cn-civil-code-20210101:art:577',
    '《中华人民共和国民法典》第五百七十七条'
  ),
  (
    'cite-labor-contract-10',
    'cn-labor-contract-law-20130701-10',
    'law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:10',
    '《中华人民共和国劳动合同法》第十条'
  ),
  (
    'cite-labor-contract-36',
    'cn-labor-contract-law-20130701-36',
    'law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:36',
    '《中华人民共和国劳动合同法》第三十六条'
  ),
  (
    'cite-labor-contract-82',
    'cn-labor-contract-law-20130701-82',
    'law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:82',
    '《中华人民共和国劳动合同法》第八十二条'
  ),
  (
    'cite-contract-law-107',
    'cn-contract-law-19991001-107',
    'law:cn-contract-law-1999:cn-contract-law-19991001:art:107',
    '《中华人民共和国合同法》第一百零七条'
  );

INSERT INTO law_articles_fts (
  rowid,
  article_id,
  document_id,
  version_id,
  document_title,
  article_number,
  article_title,
  content
)
SELECT
  law_articles.rowid,
  law_articles.id,
  law_articles.document_id,
  law_articles.version_id,
  law_documents.title,
  law_articles.article_number,
  COALESCE(law_articles.title, ''),
  law_articles.content
FROM law_articles
JOIN law_documents ON law_documents.id = law_articles.document_id;

COMMIT;
