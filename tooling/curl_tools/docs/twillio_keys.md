# How to get API keys
Go to [Twilio login page](https://www.twilio.com/login) and follow the following steps:

1. After creating a phone number and being verified, go to "Account Dashboard"
2. Scroll down to "Account Info"
3. Create `.env` and add your "Account SID", "Auth Token" and "My Twilio phone number" as follows:
    ```sh
    TWILIO_ACCOUNT_SID=your-account-sid-here
    TWILIO_AUTH_TOKEN=your-auth-token-here
    TWILIO_FROM_NUMBER=your-twilio-phone-number-with-country-and-area-codes
    ```