# Function to display the main menu
Function Show-MainMenu {
    Clear-Host # Clear the screen before showing the menu
    Write-Host "`n      Welcome to Shadowman!            " -ForegroundColor Black -BackgroundColor Red
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    Write-Host "1) Run Basic Audit (Full Report)       " -ForegroundColor Black -BackgroundColor white
    Write-Host "2) Run Targeted Risk Audit             " -ForegroundColor Black -BackgroundColor white
    Write-Host "3) Setup Active Defense                " -ForegroundColor Black -BackgroundColor white
    Write-Host "4) About & Help                        " -ForegroundColor Black -BackgroundColor white
    Write-Host "5) Exit                                " -ForegroundColor Black -BackgroundColor white
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
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -Confirm:$false
    }

    Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "DelegatedPermissionGrant.Read.All" -NoWelcome
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
            # View & Configure Settings (Future)
            Write-Host "This feature is coming in a future version!" -ForegroundColor Cyan
            Read-Host "Press Enter to return to menu."
            Clear-Host
        }
        "4" {
            # About & Help
            Write-Host "Shadowman v1.0. A tool to uncover user-consented apps in your M365 tenant." -ForegroundColor Green
            Write-Host "Author: Your Name Here" -ForegroundColor Green
            Write-Host "Required Graph API Scopes: Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All" -ForegroundColor Green
            Read-Host "Press Enter to return to menu"
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
            Write-Host "Invalid choice. Please enter a number from 1 to 5." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
        }
    }
} while (-not $exitMenu)

# End of script

