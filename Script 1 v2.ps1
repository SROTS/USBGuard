$eventIdentifier = "USBInsertedEvent"

# Function to handle USB insertion events
function Handle-USBInsertionEvent {
    param (
        [string]$driveLetter
    )
    
    [Console]::WriteLine("USB Drive Inserted - Drive Letter: $driveLetter")
    
    $executablePath  = "C:\!PC_Setup\Script 2 v2.exe"

    if (Test-Path $executablePath -PathType Leaf) {
        [Console]::WriteLine("Running external executable: $executablePath")
        Start-Process -FilePath $executablePath -NoNewWindow
    } else {
        [Console]::WriteLine("please wait....")
    }
}

# Register an event to monitor USB insertion events
Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier $eventIdentifier -Action {
    $eventType = $event.SourceEventArgs.NewEvent.EventType

    if ($eventType -eq 2) {  # 2 represents "USB inserted"
        $driveLetter = $event.SourceEventArgs.NewEvent.DriveName
        Handle-USBInsertionEvent -driveLetter $driveLetter
    }
} | Out-Null  # Discard the output to suppress the table

# Keep the script running to continue monitoring
[Console]::WriteLine("Monitoring for USB insertion events.This window can be closed")

try {
    while ($true) {
        Wait-Event -SourceIdentifier $eventIdentifier | Out-Null
        Remove-Event -SourceIdentifier $eventIdentifier
    }
}
finally {
    # Clean up and unregister the event subscription when done
    Unregister-Event -SourceIdentifier $eventIdentifier
}
