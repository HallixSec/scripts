echo "[+] Scanning Services for misconfigurations: "

# Get list of all the service items and grep on the SERVICE_NAME
$services = sc.exe query | findstr "SERVICE_NAME"

# Format the line to remove uneccesary text
$services_formatted = echo $services | %{$_ -replace "SERVICE_NAME: ",""}

echo ""
echo "[!] Vulnerable Services Found: "

# loop through the service names
$file = echo $services_formatted
foreach ($line in $file){
    # get the BINARY_PATH_NAME which stores the data for the applications location on the disk
    $path = sc.exe qc $line | findstr "BINARY_PATH_NAME"

    # Get the SERVICE_START_NAME value which stores what user the service will be run as 
    $user = sc.exe qc $line | findstr "SERVICE_START_NAME"

    # Some formatting to remove unessecary text
    $path_formatted = %{$path -replace "        BINARY_PATH_NAME   : ",""}
    $user_formatted = %{$user -replace "        SERVICE_START_NAME : ",""}

    # We use this to clean up the path removing any command line arguements and store it in $path_short
    if ($path_formatted -match '^[A-Z]:\\[a-zA-Z\\0-9\(\)\~ _.-]{1,}.exe' ) { $path_short = $matches[0] }

    # We check the permissions for each file in icacls and get some data for later
    $icacls = icacls $path_short
    $icacls_EVERYONE = $icacls | findstr "Everyone"
    $icacls_USER = $icacls | findstr "Users"

    # some formatting to remove the extra spacing
    $icacls_USER_formatted = %{$icacls_USER -replace " ",""}
    $icacls_EVERYONE_formatted = %{$icacls_EVERYONE -replace " ",""}

    # If we get (W)(M)(F) in the users permissions, then display
    if ($icacls_USER_formatted -match '\(W\)|\(M\)|\(F\)'){
        echo "[!] File: ${path_short}: "
        echo "[!] Run's as: ${user_formatted}"
        if ($icacls_USER_formatted -match '\(W\)|\(M\)|\(F\)'){$icacls_USER_formatted = $matches[0]}
        echo "[!] User Group Permissions: $icacls_USER_formatted"
        echo ""
    }

    # If we get (W)(M)(F) in everyone permissions, then display
    if ($icacls_EVERYONE_formatted -match '\(W\)|\(M\)|\(F\)'){
        echo "[!] File: ${path_short}: "
        echo "[!] Run's as: ${user_formatted}"
        if ($icacls_EVERYONE_formatted -match '\(W\)|\(M\)|\(F\)'){$icacls_EVERYONE_formatted = $matches[0]}
        echo "[!] User Group Permissions: $icacls_EVERYONE_formatted"
        echo ""
    }    
}

# Check if the file path contains a space character and the path is unquoted
echo "[+] Checking for Unquoted Service Paths: "

# Loop through the service names
foreach ($line in $file){
    # get the BINARY_PATH_NAME which stores the data for the applications location on the disk
    $path = sc.exe qc $line | findstr "BINARY_PATH_NAME"

    # Get the SERVICE_START_NAME value which stores what user the service will be run as 
    $user = sc.exe qc $line | findstr "SERVICE_START_NAME"

    # Some formatting to remove unessecary text
    $path_formatted = %{$path -replace "        BINARY_PATH_NAME   : ",""}
    $user_formatted = %{$user -replace "        SERVICE_START_NAME : ",""}

    # We use this to clean up the path removing any command line arguements and store it in $path_short
    if ($path_formatted -match '^[A-Z]:\\[a-zA-Z\\0-9\(\)\~ _.-]{1,}.exe' ) { $path_short = $matches[0] }

    # Check if the path contains a space character and output
    if ($path_short.Contains(' ') ) { echo "[!] Path: ${path_short}" } 
}

echo ""
echo "[+] Check if the directory has AD/WD permissions with icacls"

# loop through the service names
$file = echo $services_formatted

$user_option = Read-Host "[+] Run SERVICE_ALL_ACCESS check? (Y/N) This will output a lot of information!"
if ($user_option.ToString().ToUpper() -eq "Y") {
    echo ""
    echo "[+] Checking for SERVICE_ALL_ACCESS servers"
    # Check for services with SERVICE_ALL_ACCESS set (This will display for all groups)
    foreach ($line in $file){

        $services = accesschk64.exe -w -qlc $line
        [System.Collections.ArrayList] $services_array = @()
        
        $services | foreach {
            $line=$_-Split"\n".ToString()
            $services_array += %{$line -replace "`t", "" -replace " ",""}
        }

        # Remove program name, version details etc
        $services_array.RemoveRange(0,5)
        $service_name = $services_array[0]

        $services_string = ""
        $services_array | foreach {
            if ($_ -notcontains "[SE_DACL_PRESENT]" -and $_ -notcontains "[SE_SACL_PRESENT]" -and $_ -notcontains "[SE_SELF_RELATIVE]" -and $_ -notcontains "DESCRIPTORFLAGS:") {
                $services_string += "$_;"
                if ("SERVICE_ALL_ACCESS" -in $_) {             
                    echo "[!] $service_name"
                    $ser_array = $services_string -split ";" -replace $service_name, ""
                    echo $ser_array
                    echo ""
                }
            }
        }    
    } 
} elseif ($user_option.ToString().ToUpper() -eq "N") {
    echo "[!] Goodbye"
    break
} else {
    echo "[!] Invalid Option, Quitting!!"
    break
}