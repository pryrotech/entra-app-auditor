# Function to display the main menu
Function Show-MainMenu {
    Clear-Host # Clear the screen before showing the menu
    Write-Host "`n      Welcome to Shadowman!            " -ForegroundColor Black -BackgroundColor Red
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "1) Run Basic Audit (Full Report)       " -ForegroundColor Black -BackgroundColor white
    Write-Host "2) Run Targeted Risk Audit             " -ForegroundColor Black -BackgroundColor white
    Write-Host "3) Advanced Security Signals Audit     " -ForegroundColor Black -BackgroundColor white
    Write-Host "4) About & Help                        " -ForegroundColor Black -BackgroundColor white
    Write-Host "5) Exit                                " -ForegroundColor Black -BackgroundColor white
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n"
}

# Function to display security signals menu
Function Show-SecuritySignalsMenu {
    Clear-Host
    Write-Host "`n   Advanced Security Signals Audits     " -ForegroundColor Black -BackgroundColor Cyan
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "1) Identity & Sign-In Risk Signals     " -ForegroundColor Black -BackgroundColor white
    Write-Host "2) OAuth & Consent Signals             " -ForegroundColor Black -BackgroundColor white
    Write-Host "3) Service Principal Activity          " -ForegroundColor Black -BackgroundColor white
    Write-Host "4) Token & Session Security            " -ForegroundColor Black -BackgroundColor white
    Write-Host "5) Conditional Access Signals          " -ForegroundColor Black -BackgroundColor white
    Write-Host "6) Permissions & Role Signals          " -ForegroundColor Black -BackgroundColor white
    Write-Host "7) Usage & Activity Signals            " -ForegroundColor Black -BackgroundColor white
    Write-Host "8) Environment & Posture Signals       " -ForegroundColor Black -BackgroundColor white
    Write-Host "9) Run All Security Signals Audits     " -ForegroundColor Black -BackgroundColor yellow
    Write-Host "0) Return to Main Menu                 " -ForegroundColor Black -BackgroundColor white
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n"
}

# Function to get user choice
Function Get-UserMenuChoice {
    Read-Host "Enter a number and press ENTER"
}


# --- Your ASCII Banner (can be a separate function too, if desired) ---
$ascii = @"
 _____    __    __     ____   ______      ____      ___        ___       __    __       ____          __      _ 
/ ____\  (  \  /  )   (    )  (_  __\    / __ \    (  (        )  )      \ \  / /      (    )        /  \    / )
( (___    \ (__) /   / /\ \    ) ) \ \   / /  \ \   \  \  _  /  /        () \/ ()      / /\ \       / /\ \  / / 
 \___ \    ) __ (   ( (__) )  ( (   ) ) ( ()  () )   \  \/ \/  /         / _  _ \     ( (__) )     ) ) ) ) ) ) 
     ) )  ( (  ) )   )    (    ) )  ) ) ( ()  () )    )   _   (         / / \/ \ \     )    (     ( ( ( ( ( ( 
 ___/ /    ) )( (   /  /\  \  / /__/ /   \ \__/ /     \  ( )  /        /_/      \_\   /  /\  \    / /  \ \/ / 
/____/    /_/  \_\ /__(  )__\(______/     \____/       \_/ \_/        (/          \) /__(  )__\  (_/    \__/  
"@.Split("`n")

Clear-Host # Clear the screen before showing the banner
foreach ($line in $ascii) {
    Write-Host $line -ForegroundColor Red -BackgroundColor Black
}
Start-Sleep -Seconds 3 # Give time to view banner

# --- Initial Microsoft Graph Connection (one-time check at script start) ---
Write-Host "`nConnecting to Microsoft Graph...." -ForegroundColor yellow -BackgroundColor black
try {
    # Ensure modules are installed and profile is selected (from previous recommendations)
    # This block is usually placed at the very top of your main script file
    # for clarity, but works here too.
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Warning "Microsoft.Graph PowerShell module not found. Attempting to install for CurrentUser."
        #Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -Confirm:$false
    }

    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AuditLog.Read.All",
        "User.Read.All",
        "Policy.Read.All"
    ) -NoWelcome 
    Write-Host "Connected successfully!                             " -ForegroundColor Black -BackgroundColor Green
    Start-Sleep -Seconds 2 # Short pause after connection success
    Clear-Host # Clear before showing the menu for the first time
}
catch {
    Write-Host "Error connecting to Microsoft Graph. Please check error message for details:" -ForegroundColor black -BackgroundColor red
    Write-Host $($_.Exception.Message) -ForegroundColor Red
    Write-Host "Exiting script." -ForegroundColor DarkRed
    Start-Sleep -Seconds 5
    exit # Exit script immediately if connection fails
}

# --- Main Menu Loop ---
$exitMenu = $false
do {
    Show-MainMenu # Display the menu
    $userInput = Get-UserMenuChoice # Get user's choice

    switch ($userInput) {
        "1" {
            .\basic-audit.ps1
        }
        "2" {
            .\targeted-audit.ps1
        }
        "3" {
            # Advanced Security Signals Audit submenu
            $exitSignalsMenu = $false
            do {
                Show-SecuritySignalsMenu
                $signalChoice = Get-UserMenuChoice
                
                switch ($signalChoice) {
                    "1" {
                        .\identity-risk-audit.ps1
                    }
                    "2" {
                        .\oauth-consent-audit.ps1
                    }
                    "3" {
                        .\service-principal-audit.ps1
                    }
                    "4" {
                        .\token-session-audit.ps1
                    }
                    "5" {
                        .\conditional-access-audit.ps1
                    }
                    "6" {
                        .\permissions-roles-audit.ps1
                    }
                    "7" {
                        .\usage-activity-audit.ps1
                    }
                    "8" {
                        .\environment-posture-audit.ps1
                    }
                    "9" {
                        Write-Host "Running all security signals audits..." -ForegroundColor Yellow
                        .\identity-risk-audit.ps1
                        .\oauth-consent-audit.ps1
                        .\service-principal-audit.ps1
                        .\token-session-audit.ps1
                        .\conditional-access-audit.ps1
                        .\permissions-roles-audit.ps1
                        .\usage-activity-audit.ps1
                        .\environment-posture-audit.ps1
                        Write-Host "All audits complete!" -ForegroundColor Green
                        Read-Host "Press Enter to continue"
                        Clear-Host
                    }
                    "0" {
                        $exitSignalsMenu = $true
                    }
                    default {
                        Write-Host "Invalid choice. Please enter a number from 0 to 9." -ForegroundColor Red
                        Start-Sleep -Seconds 2
                    }
                }
            } while (-not $exitSignalsMenu)
            
            Clear-Host
        }
        "4" {
            # About & Help
            Write-Host "`n" -ForegroundColor White
            Write-Host "Shadowman v2.0 - Advanced Entra ID Security Audit Tool" -ForegroundColor Green
            Write-Host "==========================================================" -ForegroundColor Green
            Write-Host "`nFeatures:" -ForegroundColor Cyan
            Write-Host "  - Basic OAuth consent and permission audits" -ForegroundColor Gray
            Write-Host "  - Targeted risk assessments" -ForegroundColor Gray
            Write-Host "  - Identity & Sign-In Risk Detection" -ForegroundColor Gray
            Write-Host "  - OAuth & Consent Pattern Analysis" -ForegroundColor Gray
            Write-Host "  - Service Principal Activity Monitoring" -ForegroundColor Gray
            Write-Host "  - Token & Session Security Analysis" -ForegroundColor Gray
            Write-Host "  - Conditional Access Signal Detection" -ForegroundColor Gray
            Write-Host "  - Permission & Role Assignment Review" -ForegroundColor Gray
            Write-Host "  - Usage & Activity Pattern Analysis" -ForegroundColor Gray
            Write-Host "  - Environment & Posture Assessment" -ForegroundColor Gray
            Write-Host "`nRequired Graph API Scopes:" -ForegroundColor Cyan
            Write-Host "  - Application.Read.All" -ForegroundColor Gray
            Write-Host "  - Directory.Read.All" -ForegroundColor Gray
            Write-Host "  - DelegatedPermissionGrant.Read.All" -ForegroundColor Gray
            Write-Host "  - AuditLog.Read.All" -ForegroundColor Gray
            Write-Host "  - User.Read.All" -ForegroundColor Gray
            Write-Host "  - Policy.Read.All" -ForegroundColor Gray
            Read-Host "`nPress Enter to return to menu"
            Clear-Host
        }
        "5" {
            # Exit
            Write-Host "Exiting Shadowman. Goodbye!" -ForegroundColor Magenta
            $exitMenu = $true # Set flag to exit the loop
            Disconnect-MgGraph # Disconnect from Graph
            Start-Sleep -Seconds 2
        }
        default {
            Write-Host "Invalid choice. Please enter a number from 1 to 6." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
        }
    }
} while (-not $exitMenu)
    


# End of script

