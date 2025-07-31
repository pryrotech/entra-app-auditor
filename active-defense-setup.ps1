# Function to display the main menu
Function Show-ADMenu {
    Clear-Host # Clear the screen before showing the menu
    Write-Host "`n     Active Defense for Shadowman      " -ForegroundColor White -BackgroundColor Magenta
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "1) Setup Active Defense                " -ForegroundColor Black -BackgroundColor white
    Write-Host "2) Modify Alerts                       " -ForegroundColor Black -BackgroundColor white
    Write-Host "3) Remove Active Defense               " -ForegroundColor Black -BackgroundColor white
    Write-Host "4) About Active Defense                " -ForegroundColor Black -BackgroundColor white
    Write-Host "5) Exit                                " -ForegroundColor Black -BackgroundColor white
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n"
}

# Function to get user choice
Function Get-ADMenuChoice {
    Read-Host "Enter a number and press ENTER"
}


# --- Main Menu Loop ---
$exitMenu = $false
do {
    Show-ADMenu # Display the menu
    $userInput = Get-ADMenuChoice # Get user's choice

    switch ($userInput) {
        "1" {
            Write-Host "Shadowman will now attempt to setup Active Defense. Please run this section with administrative privileges." -ForegroundColor yellow -BackgroundColor black
            Read-Host "Press Enter if you have administrative privileges...."
            Write-Host "You will now be prompted to set flags. These flags are the criteria that will be used when Active Defense is executed:" -ForegroundColor yellow -BackgroundColor black
        }
        "2" {
            .\targeted-audit.ps1
        }
        "3" {
            # View & Configure Settings (Future)
            Write-Host "This feature is coming in a future version!" -ForegroundColor Cyan
            Read-Host "Press Enter to return to menu."
            Clear-Host
        }
        "4" {
            # About & Help
            Write-Host "Active Defense is a module provided by Shadowman that scans your M365 tenant for changes in user-consented apps." -ForegroundColor Magenta
            Write-Host "You can set Active Defense to alert you with the following flags:" -ForegroundColor Magenta
            Write-Host "`n-App with risky permissions added" -ForegroundColor Magenta
            Write-Host "-App with unverified publisher added" -ForegroundColor Magenta
            Write-Host "-App added has 'full_access_as_app' attribute" -ForegroundColor Magenta
            Write-Host "-App added has high user consent count" -ForegroundColor Magenta
            Write-Host "-App added has external tenant access" -ForegroundColor Magenta
            Write-Host "-App added originates from a certain country or region" -ForegroundColor Magenta
            Write-Host "-App added is not account enabled, but has new consent" -ForegroundColor Magenta
            Write-Host "-App added is orphaned" -ForegroundColor Magenta
            Write-Host "-App added has consent from a high-value user" -ForegroundColor Magenta
            Write-Host "-App added has broad access to all mailboxes or calendars" -ForegroundColor Magenta
            Write-Host "-App added has read and write access for a sensitive resource" -ForegroundColor Magenta
            Write-Host "`nTo use Active Defense, please select the setup option from the menu. From here, you will be given an option to" -ForegroundColor Magenta
            Write-Host "set the flags you desire, set the alerting parameter and give consent for Shadowman to auto-remediate if you wish to do so." -ForegroundColor Magenta
            Write-Host "`nNOTE: This will not work for apps added prior to Active Defense being enabled. You will need to audit and remediate these manually." -ForegroundColor Red
            Read-Host "Press Enter to return to menu"
            Clear-Host
        }
        "5" {
            # Exit
            .\entra-app-auditor-main.ps1
        }
        default {
            Write-Host "Invalid choice. Please enter a number from 1 to 5." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
        }
    }
} while (-not $exitMenu)

# End of script