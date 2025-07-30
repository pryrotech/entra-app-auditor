Import-Module Microsoft.Graph

$ascii = @"

  _____   __    __     ____     ______       ____     ___       ___     __    __       ____        __      _  
 / ____\ (  \  /  )   (    )   (_  __ \     / __ \   (  (       )  )    \ \  / /      (    )      /  \    / ) 
( (___    \ (__) /    / /\ \     ) ) \ \   / /  \ \   \  \  _  /  /     () \/ ()      / /\ \     / /\ \  / /  
 \___ \    ) __ (    ( (__) )   ( (   ) ) ( ()  () )   \  \/ \/  /      / _  _ \     ( (__) )    ) ) ) ) ) )  
     ) )  ( (  ) )    )    (     ) )  ) ) ( ()  () )    )   _   (      / / \/ \ \     )    (    ( ( ( ( ( (   
 ___/ /    ) )( (    /  /\  \   / /__/ /   \ \__/ /     \  ( )  /     /_/      \_\   /  /\  \   / /  \ \/ /   
/____/    /_/  \_\  /__(  )__\ (______/     \____/       \_/ \_/     (/          \) /__(  )__\ (_/    \__/ 

"@.Split("`n") 

foreach ($line in $ascii) {
    Write-Host $line -ForegroundColor Red -BackgroundColor black
}


try {
    Write-Host "Connecting to Microsoft Graph...." -ForegroundColor yellow -BackgroundColor black
    Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All" -NoWelcome
    $getProfile = $True

    if ($getProfile) {
        Write-Host "Connected successfully! Profile: $($getProfile.Name)" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep -Seconds 5
        Clear-Host
        Write-Host "`n      Welcome to Shadowman ver 0.0.1!        " -ForegroundColor Black -BackgroundColor Red
        Write-Host "1) Run Basic Audit (Full Report)             " -ForegroundColor Black -BackgroundColor white
        Write-Host "2) Run Targeted Risk Audit                   " -ForegroundColor Black -BackgroundColor white
        Write-Host "3) View & Configure Settings                 " -ForegroundColor Black -BackgroundColor white
        Write-Host "4) About & Help                              " -ForegroundColor Black -BackgroundColor white
        Write-Host "5) Exit                                      " -ForegroundColor Black -BackgroundColor white
        Write-Host "                                             `n" -ForegroundColor Black -BackgroundColor Red
        
    } else {
        Write-Host "Connected, but unable to retrieve profile info." -ForegroundColor DarkYellow
    }
}
catch {
    Write-Host "Connection to Microsoft Graph failed, please see error message for more details:" -ForegroundColor black -BackgroundColor red
    Write-Host $($_.Exception.Message)
}

