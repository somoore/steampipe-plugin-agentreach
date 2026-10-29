# Table: agentreach_marketplace

One row per plugin marketplace registered in `known_marketplaces.json`. A marketplace is a catalog the agent can install plugins from, so the set of marketplaces is the plugin supply chain. The table shows each marketplace's source, whether it auto-updates, whether it is Anthropic's official one, and whether a managed `strictKnownMarketplaces` allowlist admits it.

## Examples

### Basic info

```sql
select
  name,
  source_type,
  source_repo,
  official,
  auto_update
from
  agentreach_marketplace;
```

### List unofficial marketplaces

```sql
select
  name,
  source_type,
  source_repo,
  last_updated
from
  agentreach_marketplace
where
  not official;
```

### Check marketplaces against the strict allowlist

`in_strict_allowlist` is null when no `strictKnownMarketplaces` policy exists at all, which is the common case on an unmanaged machine.

```sql
select
  name,
  source_repo,
  in_strict_allowlist
from
  agentreach_marketplace
where
  in_strict_allowlist is distinct from true;
```

### Find marketplaces that refresh themselves

```sql
select
  name,
  source_repo,
  auto_update
from
  agentreach_marketplace
where
  auto_update;
```

### Join plugins to the marketplace they came from

```sql
select
  p.full_name,
  m.source_type,
  m.source_repo,
  m.official
from
  agentreach_plugin p
  left join agentreach_marketplace m on m.name = p.marketplace
order by
  m.official,
  p.full_name;
```
