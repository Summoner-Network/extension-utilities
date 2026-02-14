# How to get API keys

*Reference: [https://support.mothernode.com/knowledge-base/api-key/](https://support.mothernode.com/knowledge-base/api-key/)*


Mothernode CRM users who wish to connect with third-party services via API can do so using one of Mothernode’s API keys. API keys are generated at the user level and can be managed by Admins in the user’s account.

1. Go to `Adminitration>User Account>Permissions`
2. Click the Administration Tab
3. Open a user profile record
4. Click the permissions tab
5. Select "Allow Access" and "Access to Contacts"
6. Create `.env` and add both you "Access Key" and "API Password" as follows:
    ```sh
    MOTHERNODE_ACCESS_KEY=your-access-key-here
    MOTHERNODE_API_PASSWORD=your-api-password-here
    ```
