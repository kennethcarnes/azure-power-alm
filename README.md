# Introduction 
This project uses Azure Pipelines, Repos, and Service Principal for CI/CD of Power Platform Solutions. Everything in this repository was adapted from this [Power Platform Build Tools](https://github.com/microsoft/PowerApps-Samples/tree/master/build-tools) repository by Microsoft. All credit goes to that team.

<!---
Download the Visio package by [sandroasp](https://github.com/sandroasp/Microsoft-Integration-and-Azure-Stencils-Pack-for-Visio).
Diagram in progress.
-->
 
## Getting Started 
To get started, follow the steps below: 

1. [Create the DEV, BUILD, and PROD environments in the Power Platform Admin Center.](https://learn.microsoft.com/en-us/power-platform/admin/create-environment#create-an-environment-in-the-power-platform-admin-center)
2. Create an Azure AD service principal and client secret using the [PowerShell script provided by Microsoft](https://pabuildtools.blob.core.windows.net/spn-docs-4133a3fe/New-CrmServicePrincipal.ps1).

    ```powershell
    .\New-CrmServicePrincipal.ps1
    ```
    
> **Note**
> Steps to complete this manually can be found at this link: https://learn.microsoft.com/en-us/powerapps/developer/common-data-service/use-single-tenant-server-server-authentication#azure-application-registration

3. To finish configuring the Service Principal, use the Application ID and Client Secret from the previous step to configure an [Application User](https://learn.microsoft.com/en-us/powerapps/developer/common-data-service/use-single-tenant-server-server-authentication#application-user-creation) with the System Administrator role in each environment.

4. Create pipelines in Azure DevOps.

| File Name                  | Description                                                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| export-from-dev.yml        | Exports an unmanaged solution from the DEV environment, then unpacks, commits, and pushes it to the code repository.               |
| build-managed-solution.yml | Builds a managed solution using the Power Platform Build Tools, imports it into the build environment, and exports it to Artifacts as a managed solution. |
| release-to-prod.yml        | Imports a managed solution into the PROD environment using the Power Platform Import Solution task.                                 |
   
5. Add a variable group with the variables below.

| Variable            | Description                                                                                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $(PowerPlatformSPN) | The name of the service principal that has been granted permission to perform operations on the Power Platform environments. |
| $(SolutionName)     | The name of the solution to be exported |

## Documentation 
Refer to the following resources for more information about Power Platform Build Tools:

- [Power Platform Build Tools documentation](https://learn.microsoft.com/en-us/power-platform/alm/devops-build-tools#get-microsoft-power-platform-build-tools)
- [Setting up Power Platform Build Tools](https://learn.microsoft.com/en-us/power-platform/alm/devops-build-tools)
- [Power Platform Build Tools Marketplace](https://marketplace.visualstudio.com/items?itemName=microsoft-IsvExpTools.PowerPlatform-BuildTools)
