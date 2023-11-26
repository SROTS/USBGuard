$shell = New-Object -ComObject WScript.Shell
$eventIdentifier = "USBInsertedEvent"
$scriptHasRun = $false

# Function to display a pop-up notification
function Show-Notification {
    param (
        [string]$Title,
        [string]$Message
    )
    $shell.Popup($Message, 0, $Title, 64) | Out-Null
}


# Function to start a scan using Microsoft Defender with specific paths to scan
function Start-DefenderScan {
    param (
        [string[]]$ScanPaths
    )
    $scanPathsParam = "-ScanPath " + ($ScanPaths -join ",")
    $defenderCommand = "Start-MpScan -ScanType QuickScan $scanPathsParam"
    Invoke-Expression $defenderCommand
}

# Function to check if a scan is currently running
function Is-DefenderScanRunning {
    $scanStatus = Get-MpComputerStatus
    return $scanStatus.AntivirusScanStatus -eq "Running"
}

# Function to check if malicious software is detected
function Is-MaliciousSoftwareDetected {
    $scanResults = Get-MpThreatDetection
    return $scanResults | Where-Object { $_.DetectionStatus -eq "Detected" -and $_.PathType -eq "LocalFixedDrive" } | ForEach-Object { $true }
}

# Function to eject the USB device
function Eject-UsbDevice {
    param (
        [string]$DriveLetter
    )
    $ejectCommand = "Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\usbstor' -Name '$DriveLetter' -ErrorAction SilentlyContinue"
    Invoke-Expression $ejectCommand
}

# Function to display a pop-up notification when the scan is complete
function Show-ScanCompleteNotification {
    Show-Notification -Title "Scan Complete" -Message "Virus scan is complete."
    Stop-Process -Id $PID
}

# Function to handle the entire process for a USB device
function Handle-UsbDevice {
    param (
        [string]$usbDrivePath
    )

    Show-Notification -Title "USB Device Inserted" -Message "A USB device has been inserted."

    # Start the Defender scan on the USB drive
    Start-DefenderScan -ScanPaths $usbDrivePath

    # Wait for the scan to complete
    while (Is-DefenderScanRunning) {
        Start-Sleep -Seconds 5
    }

    # After the scan is complete, open Windows Security
    Start-Process "explorer" "windowsdefender:"

    # Check if malicious software was detected on the USB drive
    if (Is-MaliciousSoftwareDetected) {
        Show-Notification -Title "Malicious Software Detected" -Message "Malicious software was detected during the scan on the USB device. It has been reported to I.T."
        Eject-UsbDevice -DriveLetter $usbDrivePath
    } else {
        Show-ScanCompleteNotification
    }
}

# Function to detect and process existing USB devices
function Detect-AndProcess-ExistingUSBDevices {
    $usbDriveLetters = Get-WmiObject -Query "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'" | ForEach-Object {
        Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($_.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition" | ForEach-Object {
            $_.DeviceID
        } | ForEach-Object {
            Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$_'} WHERE AssocClass=Win32_LogicalDiskToPartition" | ForEach-Object {
                $_.DeviceID
            }
        }
    }

    foreach ($driveLetter in $usbDriveLetters) {
        Handle-UsbDevice -usbDrivePath $driveLetter
    }
}

# Detect and process existing USB devices when the script starts
if (-not $scriptHasRun) {
    Detect-AndProcess-ExistingUSBDevices
    $scriptHasRun = $true
}

# Monitor for USB insertion events
$usbWatcher = Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier $eventIdentifier -Action {
    $eventType = $event.SourceEventArgs.NewEvent.EventType

if ($eventType -eq 2 -or $eventType -eq 3) {  # 2 represents "Volume Insert" and 3 represents "Volume Remove"
    $usbDriveLetter = $event.SourceEventArgs.NewEvent.DriveName
    $usbDrivePath = $usbDriveLetter + "\"

    Handle-UsbDevice -usbDrivePath $usbDrivePath
}

}

# Display pop-up notification
Show-Notification -Title "USB Device Monitoring" -Message "USBMonitor activated - please remove and insert the USB stick again for a virus scan."

try {
    while ($true) {
        # Wait for USB events
        Wait-Event -SourceIdentifier $eventIdentifier | Out-Null
        Remove-Event -SourceIdentifier $eventIdentifier
    }
} finally {
    # Clean up and unregister the event subscription
    Unregister-Event -SourceIdentifier $eventIdentifier
}
