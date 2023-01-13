# Terraform keycloack initiation

This terraform module is used to initiate newly created keycloack realm.

## Pre-requisite

To be able to deploy this module credentials have to be created in the keycloack.  
For this, a keycloack client have to be configured, then the credential of this client can be used to deploy this terraform module.

### Creating the keycloack client

1. Connect to the new keycloack realm
2. Select the client tabs on the left and click on `create` on the top right
3. Import this [configuration](resources/terraform.json) and click `save`
4. Regenerate the credentials in the newly created terraform client
    - Click on `edit` for the terraform client
    - Select `Credentials` and click on `regenerate Secret`
5. Terraforn can now be executed with this command:
    - `terraform plan -var "kc_terraform_auth_password=<Secret>" -var "kc_base_url=<keycloack_realm_url>" -var "cloudfront_auth_url=<cloudfront_url>"`
