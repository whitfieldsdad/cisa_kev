from cisa_kev.client import Client

import polars as pl

# Hide log line indicating dataframe shape, allow unlimited output rows.
pl.Config.set_tbl_hide_dataframe_shape(True) 
pl.Config.set_tbl_rows(-1)

client = Client()

df = client.get_catalog_as_polars_dataframe()

# Get all Microsoft vulnerabilities related to ransomware campaigns (polars)
with pl.SQLContext(df=df, eager_execution=True) as ctx:
    query = """
    SELECT 
        cve_id, 
        vendor, 
        product, 
        date_added, 
        due_date 
    FROM df 
    WHERE known_ransomware_campaign_use = true AND vendor ILIKE '%microsoft%' 
    ORDER BY date_added ASC
    """
    result = ctx.execute(query)
    print(result)

