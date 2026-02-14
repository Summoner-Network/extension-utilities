# How to get API keys
Go to the [Hubspot login page](https://app-na2.hubspot.com/login), enter the web app and follow the following steps:

1. Go to setting ⚙️ (the small cog symbol on the top-right)
2. Integration > Legacy Apps
3. `Create legacy App` on the right
4. Add scopes:
    ```
    crm.schemas.quotes.read
    crm.objects.subscriptions.write
    crm.objects.line_items.read
    crm.schemas.subscriptions.write
    crm.objects.line_items.write
    crm.schemas.invoices.write
    crm.schemas.line_items.read
    crm.objects.goals.write
    crm.objects.products.read
    tickets
    crm.objects.products.write
    crm.objects.commercepayments.write
    crm.objects.projects.write
    crm.schemas.commercepayments.write
    crm.objects.projects.read
    crm.objects.goals.read
    crm.objects.contacts.read
    crm.objects.partner-services.read
    crm.objects.partner-services.write
    crm.schemas.projects.read
    crm.objects.subscriptions.read
    crm.schemas.subscriptions.read
    crm.schemas.projects.write
    crm.schemas.commercepayments.read
    crm.objects.commercepayments.read
    crm.objects.invoices.read
    crm.schemas.invoices.read
    crm.objects.users.read
    crm.objects.contacts.write
    crm.objects.users.write
    crm.objects.marketing_events.read
    crm.objects.marketing_events.write
    crm.schemas.custom.read
    crm.objects.custom.read
    crm.objects.custom.write
    crm.schemas.custom.write
    crm.objects.companies.write
    crm.schemas.contacts.read
    crm.schemas.carts.write
    crm.schemas.carts.read
    crm.objects.carts.write
    crm.objects.carts.read
    crm.schemas.orders.write
    crm.schemas.orders.read
    crm.objects.orders.write
    crm.objects.orders.read
    crm.objects.leads.read
    crm.objects.leads.write
    crm.objects.partner-clients.read
    crm.objects.partner-clients.write
    crm.objects.feedback_submissions.read
    crm.objects.companies.read
    crm.objects.deals.read
    crm.objects.deals.write
    crm.schemas.companies.read
    crm.schemas.companies.write
    crm.schemas.contacts.write
    crm.schemas.deals.read
    crm.schemas.deals.write
    crm.objects.owners.read
    crm.objects.courses.read
    crm.objects.courses.write
    crm.objects.listings.read
    crm.objects.listings.write
    crm.objects.services.read
    crm.objects.services.write
    crm.objects.appointments.read
    crm.objects.appointments.write
    crm.objects.invoices.write
    crm.schemas.services.read
    crm.schemas.services.write
    crm.schemas.courses.read
    crm.schemas.courses.write
    crm.schemas.listings.read
    crm.schemas.listings.write
    crm.objects.quotes.write
    crm.schemas.appointments.read
    crm.objects.quotes.read
    crm.schemas.appointments.write
    ```
5. Once the app is created, go to auth and copy the "Access token"
6. Create `.env` and add your "Access token" as follows:
    ```sh
    HUBSPOT_ACCESS_TOKEN=you-access-token-here
    ```