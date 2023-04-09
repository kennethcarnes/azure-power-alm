# Introduction 
This project aims to guide users on how to create pipelines to build and deploy Power Platform solutions using Azure DevOps. The motivation behind this project is to provide a step-by-step process to help users manage their Power Platform solutions efficiently.

## Credit 
The pipelines used in this project are adapted from the [PowerApps-Samples](https://github.com/microsoft/PowerApps-Samples/tree/master/build-tools) repository by Microsoft. 

 Download the Visio package by [sandroasp](https://github.com/sandroasp/Microsoft-Integration-and-Azure-Stencils-Pack-for-Visio).
 
## Getting Started 
To get started, follow the steps below: 

1. Create the desired number of Power Platform environments.
2. Create an Azure AD service principal and client secret using the PowerShell script provided by Microsoft:

    ```powershell
    .\New-CrmServicePrincipal.ps1
    ```

Use the output from the previous step to configure an [Application User](https://learn.microsoft.com/en-us/powerapps/developer/common-data-service/use-single-tenant-server-server-authentication#application-user-creation) with the System Administrator role in each environment.
nt-server-server-authentication#application-user-creation).

### Create pipelines in Azure DevOps

| File Name                  | Description                                                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| export-from-dev.yml        | Exports an unmanaged solution from the DEV environment, then unpacks, commits, and pushes it to the code repository.               |
| build-managed-solution.yml | Builds a managed solution using the Power Platform Build Tools, imports it into the build environment, and exports it to Artifacts as a managed solution. |
| release-to-prod.yml        | Imports a managed solution into the PROD environment using the Power Platform Import Solution task.                                 |

   
### Add a variable group with the variables below.

| Variable            | Description                                                                                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $(PowerPlatformSPN) | The name of the service principal that has been granted permission to perform operations on the Power Platform environments. |
| $(SolutionName)     | The name of the solution to be exported |

## Documentation 
Refer to the following resources for more information about Power Platform Build Tools:

- [Power Platform Build Tools documentation](https://learn.microsoft.com/en-us/power-platform/alm/devops-build-tools#get-microsoft-power-platform-build-tools)
- [Setting up Power Platform Build Tools](https://learn.microsoft.com/en-us/power-platform/alm/devops-build-tools)
- [Power Platform Build Tools Marketplace](https://marketplace.visualstudio.com/items?itemName=microsoft-IsvExpTools.PowerPlatform-BuildTools)