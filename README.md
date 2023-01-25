# Terraform keycloack initiation

This terraform module is used to initiate newly created keycloack realm.

## Pre-requisite

To be able to deploy this module credentials have to be created in the keycloack.  
For this, a keycloack client have to be configured, then the credential of this client can be used to deploy this terraform module.

Also, with the keyclaock gold realm configuration, the OIDC integration have to be requested to the SSO team.
To do this this request the step 1 of this [documents](https://stackoverflow.developer.gov.bc.ca/questions/864/891).
Once the request is fulfilled, the `client_id` and `client_secret` will be provided in the SSO team CSS app.

### Creating the keycloack client

1. Connect to the new keycloack realm
2. Select the client tabs on the left and click on `create` on the top right
3. Import this [configuration](resources/terraform.json) and click `save`
4. Regenerate the credentials in the newly created terraform client
    - Click on `edit` for the terraform client
    - Select `Credentials` and click on `regenerate Secret`
5. The new terraform-service-account has to be link with roles allowing to configure the realm.
    - In the `role` tab click on the name of the role
    - In the `user in role` tab click on the username link
    - In the `role mapping` tab click on `client role` then enter in the field "realm" and select: `realm-management`
    - Now form the available role list select:
        - manage-realms
        - manage-identity-provider
        - manage-client
6. Terraforn can now be executed with this command:
    - `terraform plan -var "kc_terraform_auth_password=<Secret>" -var "kc_base_url=<keycloack_realm_url>" -var "cloudfront_auth_url=<cloudfront_url>" -var "client_id=<client_id>" -var "client_secret=<client_secret>"`
