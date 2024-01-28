from cisa_kev.client import Client

client = Client()

df = client.get_catalog_as_pandas_dataframe()

# Get all Microsoft vulnerabilities related to ransomware campaigns
df = df[df['known_ransomware_campaign_use'] == True]
df = df[df['vendor'].str.contains("microsoft", na=False, case=False)]

# Select the following columns: cve_id, vendor, product, date_added, due_date
df = df[['cve_id', 'vendor', 'product', 'date_added', 'due_date']]

# Sort by date_added
df = df.sort_values(by=['date_added'])

# Print all rows
print(df.to_string(index=False))
