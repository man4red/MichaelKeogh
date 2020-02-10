#requires -version 4
<#
.SYNOPSIS
  SMB restruct script

.DESCRIPTION
  SMB restruct script

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Version:        1.2
  Author:         man4red (it.manfred@gmail.com)
  Creation Date:  29.01.2020
  Purpose/Change: Initial script development
  1.1 - Superseded behavior changed
  1.2 - Superseded behavior changed (now it's -Superseded instead of _Superseded)
  
.EXAMPLE
  SMB-Restruct.ps1
#>

###--- PARAMETERS ---###
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$SMBRoot = "D:\ME\WORK\Other\Michael Keogh\TEST\SMBRoot",

    [Parameter(Position = 1, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$PathClients = "D:\ME\WORK\Other\Michael Keogh\TEST\Clients",

    [Parameter(Position = 2, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$PathArchive = "d:\ME\WORK\Other\Michael Keogh\TEST\Archive",

    [Parameter(Position = 3, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$PathSuperseded = "d:\ME\WORK\Other\Michael Keogh\TEST\Sharepoint\Superseded",

    [Parameter(Position = 4, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$ClientIncludeYears = (2017..2020),

    [Parameter(Position = 5, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [int]$ArchiveYearEarlierThan = 2017,
    
    [Parameter(Position = 6, Mandatory = $false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$false)]
    [string[]]$ClientCodeRenameCSV = "D:\ME\WORK\Other\Michael Keogh\DOCS\ChangeClientCode.csv"
)

###--- BEGIN EXECUTION ---###
BEGIN
{
    # GLOBAL VARS
    # Invocation Path
    $global:path = Split-Path -parent $MyInvocation.MyCommand.Definition
    # Output_log (not implemented)
    #$global:logFilePath = "$global:path\output_log.txt"

    <#        
     # Timed prompt (not used yet)
     #>   
    function TimedPrompt($prompt,$secondsToWait){   
        Write-Host -NoNewline $prompt
        $secondsCounter = 0
        $subCounter = 0
        While ( (!$host.ui.rawui.KeyAvailable) -and ($count -lt $secondsToWait) ){
            start-sleep -m 10
            $subCounter = $subCounter + 10
            if($subCounter -eq 1000)
            {
                $secondsCounter++
                $subCounter = 0
                Write-Host -NoNewline "."
            }       
            If ($secondsCounter -eq $secondsToWait) { 
                Write-Host "`r`n"
                return $false;
            }
        }
        Write-Host "`r`n"
        return $true;
    }
}

###--- PROCESS EXECUTION ---###
PROCESS
{
    <#
        1.	Superseded property 
            a.	James to produce a folder of all the superseded files
            b.	Script to scan every file in the folder
            c.	Find the file in the original location
            d.	Append “Superseded” to the original file’s name
    #>

    try { Get-Item $PathSuperseded -ErrorAction Stop | Out-Null } catch { Write-Error $_.Exception.Message; break; }

    #Get all the superseeded files
    Write-Host -ForegroundColor Gray "Get all the superseeded files... " -NoNewline
    try {
        $SuperseededFiles = Get-ChildItem "$PathSuperseded" -Depth 0
        Write-Host -ForegroundColor Green "OK"
    } catch {
        Write-Host -ForegroundColor Red "Err`: $($_.Exception.Message)"
        return
    }

    Write-Host -ForegroundColor Gray "Calculating superseeded files' hashes... "
    $resultSuperseeded = [Collections.Generic.List[Object]]($SuperseededFiles | Get-FileHash -Algorithm MD5)

    #Get all the files at the dest
    Write-Host -ForegroundColor Gray "Get all the dest files... " -NoNewline
    try {
        $DestinationFiles = Get-ChildItem "$SMBRoot" -File -Recurse:$true
        Write-Host -ForegroundColor Green "OK"
    } catch {
        Write-Host -ForegroundColor Red "Err`: $($_.Exception.Message)"
        return
    }

    Write-Host -ForegroundColor Gray "Calculating dest files' hashes... "
    foreach ($DestinationFile in $DestinationFiles) {

        try {
            $destHash = $DestinationFile | Get-FileHash -Algorithm MD5

            # check if we have hash
            Write-Host -ForegroundColor Gray "Searching for $($destHash.Path) ($($destHash.Hash)) ... "
            if ($destHash.Hash -in $resultSuperseeded.Hash) {
                # find index
                #$index = $resultSuperseeded.FindIndex( {$args[0].Hash -eq $destHash.Hash })

                $index = (0..($resultSuperseeded.Count-1)) | where {$resultSuperseeded[$_].Hash -eq $destHash.Hash}
                if ($index.Count -eq 1) {
                    Write-Host -ForegroundColor Green "`tSingle match were found $($resultSuperseeded[$index].Path) ($($resultSuperseeded[$index].Hash))"
                    
                    if ($DestinationFile.Name -ilike "*-Superseded*") {
                        Write-Host -ForegroundColor DarkYellow "`t`tSkipping already renamed file`: $($DestinationFile.FullName)..."
                        continue
                    }

                    try {
                        $newName = $DestinationFile.Name -replace $DestinationFile.Extension, "-Superseded$($DestinationFile.Extension)"
                        $DestinationFile | Rename-Item -NewName $newName
                        Write-Host -ForegroundColor Magenta "`t`t`tOK: FileRename $($DestinationFile.FullName) => ($newName)"
                    } catch {
                        Write-Error $_.Exception.Message
                    }

                } elseif ($index.Count -gt 1) {
                    Write-Host -ForegroundColor Yellow "More than 1 file were found with the same hash"
                    Write-Host -ForegroundColor Cyan "`t$($destHash.Path) ($($destHash.Hash)) matches: "
                    foreach ($el in $index) {
                        Write-Host -ForegroundColor Yellow "`t`t$($resultSuperseeded[$el].Path)"
                    }
                }

            } else {
                Write-Host -ForegroundColor Yellow "`tNo matched hash were found"
            }

        } catch {
            Write-Warning "Can't calculate hash for $($DestinationFile.Name)"
            Write-Host $_.Exception.Message
        }
    }


    ######## CLIENTS #########
    <#
        2.	Client library
            a.	Create a new top level folder = Clients
            b.	It will contain the years 2017, 2018, 2019, 2020
            c.	Copy across the data in the above years’ folder names from the existing client folders
    #>

    # Create Clients
    if (-not (Test-Path $PathClients)) {
        try {
            New-Item -ItemType Directory -Path $PathClients | Out-Null
            Write-Host -ForegroundColor Green "OK: $PathClients"
        } catch {
            Write-Error "Error: create archive $PathClients"
            return
        }
    } else {
        Write-Host -ForegroundColor Gray "OK: $PathClients (exists)"
    }

    try { Get-Item $PathClients -ErrorAction Stop | Out-Null } catch { Write-Error $_.Exception.Message; break; }
    foreach ($ClientCode in (Get-ChildItem $SMBRoot -Depth 0)) {
        # Year Subfolders
        foreach ($ClientYear in $ClientIncludeYears) {
            if (-not (Test-Path "$PathClients\$ClientCode\$ClientYear")) {
                try {
                    New-Item -ItemType Directory -Path "$PathClients\$ClientCode\$ClientYear" -Force | Out-Null
                    Write-Host -ForegroundColor Green "OK: `"$PathClients\$ClientCode\$ClientYear`" created"
                } catch {
                    Write-Error $_.Exception.Message
                }
            } else {
                Write-Host -ForegroundColor Gray "OK: `"$PathClients\$ClientCode\$ClientYear`" (exists)"
            }


            # and now copying the existing one from SMB
            if (Test-Path "$SMBRoot\$ClientCode\$ClientYear") {
                try {
                    Copy-Item -Path "$SMBRoot\$ClientCode\$ClientYear" -Destination "$PathClients\$ClientCode" -Force -Recurse
                    Write-Host -ForegroundColor Green "OK: CopyItem `"$SMBRoot\$ClientCode\$ClientYear`" -Destination `"$PathClients\$ClientCode`""
                } catch {
                    Write-Error $_.Exception.Message
                }
            } else {
                Write-Host -ForegroundColor Gray "Warn: `"$SMBRoot\$ClientCode\$ClientYear`" (not found)"
            }

        }
    }

    ######## ARCHIVE #########
    <#
        3.	Archive library
            a.	Create a new top level folder = Archive
            b.	Contains all years prior to 2017
            c.	Copy across the data in the above years’ folder names from the existing client folders 
    #>

    # Create Archive
    if (-not (Test-Path $PathArchive)) {
        try {
            New-Item -ItemType Directory -Path $PathArchive | Out-Null
            Write-Host -ForegroundColor Green "OK: $PathArchive"
        } catch {
            Write-Error "Error: create archive $PathArchive"
            return
        }
    } else {
        Write-Host -ForegroundColor Gray "OK: $PathArchive (exists)"
    }

    try { Get-Item $PathArchive -ErrorAction Stop | Out-Null } catch { Write-Error $_.Exception.Message; break; }
    foreach ($ClientCode in (Get-ChildItem $SMBRoot -Depth 0)) {
        # Year Subfolders
        foreach ($ClientYear in ($ClientCode | Get-ChildItem -Depth 0 | ?{ $_.PSIsContainer })) {

            #[int]$ClientYear.Name -lt [int]$ArchiveYearEarlierThan
            
            if ($ClientYear.Name -lt $ArchiveYearEarlierThan) {
                # pre-create folders
                try {
                    New-Item -ItemType Directory -Path "$PathArchive\$ClientCode\$ClientYear" -Force | Out-Null
                } catch {}
                # and now copying the existing one from SMB
                try {
                    Copy-Item -Path "$SMBRoot\$ClientCode\$ClientYear" -Destination "$PathArchive\$ClientCode" -Force -Recurse
                    Write-Host -ForegroundColor Green "OK: CopyItem `"$SMBRoot\$ClientCode\$ClientYear`" -Destination `"$PathArchive\$ClientCode\$ClientYear`""
                } catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
    }


    <#
        4.	Remove version text from file name
            a.	This only applies to files in the Client library (ie: years 2017 onwards - Step 2 above)
            b.	Scan all filenames
            c.	Starting from the right, find the first “_” 
            d.	Including the “_”, delete all text to the right
            e.	Eg: FactorHoldings_Y5399U.docx change to FactorHoldings.docx
    #>


    try { Get-Item $PathClients -ErrorAction Stop | Out-Null } catch { Write-Error $_.Exception.Message; break; }
    foreach ($ClientCode in (Get-ChildItem $PathClients -Depth 0)) {
        $ClientCode | Get-ChildItem -File -Recurse | %{
            if ($_.Name -match "(_(?!.*_).*?)\.") {
                $newName = $_.Name -replace $Matches[1], ""
                try {
                     $newPath = Join-Path -Path $_.Directory -ChildPath $newName
                     $_ | Move-Item -Destination $newPath -Force
                     Write-Host -ForegroundColor Green "OK: Moved file $($_.FullName) to $newPath"
                } catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
    }


        
    <#
        5.	Change ClientCode
            a.	This applies to the top level folder names (ie: ClientCode) in the Client and Archive libraries
            b.	James to provide a list of ClientCodes and Client names
            c.	Script to change all ClientCodes to Client names
    #>

    $CSV = $false

    Write-Host -ForegroundColor Gray "Importing csv from $ClientCodeRenameCSV ... " -NoNewline
    try {
        $CSV = Import-CSV -Path $ClientCodeRenameCSV -Delimiter ',' -Encoding UTF8
        Write-Host -ForegroundColor Green "OK"

        Write-Host -ForegroundColor Gray "Checking csv for required columns... " -NoNewline
        $CSVColumns = ($CSV | gm -MemberType NoteProperty)

        #Write-Host -ForegroundColor Cyan "CSV Content"
        #$CSV | ft

        #Write-Host -ForegroundColor Cyan "CSV Columns"
        #$CSVColumns | ft

        if ("ClientCode" -inotin $CSVColumns.Name) {
            Write-Error "ClientCode is missing from CSV"
            return
        } elseif ("EntityName" -inotin $CSVColumns.Name) {
            Write-Error "EntityName is missing from CSV"
            return
        } else {
            Write-Host -ForegroundColor Green "CSV looks okay..."
        }

    } catch {
        Write-Error $_.Exception.Message
        break;
    }




    # Client Part
    foreach ($ClientCode in (Get-ChildItem $PathClients -Depth 0)) {
        $newName = $false
        Write-Host -ForegroundColor Gray "Checking if $($ClientCode.Name) is in CSV ... " -NoNewline
        if ($ClientCode.Name -in $CSV.ClientCode) {

            $newName = $CSV.Where({$PSItem.ClientCode -eq $ClientCode.Name}).EntityName

            Write-Host -ForegroundColor Green "found! New name would be `"$newName`""
            if($newName -and $newName.Length -ge 1) {
                Write-Host -ForegroundColor Gray "Checking if `"$PathClients\$newName`" not exists ... " -NoNewline
                if (-not (Test-Path "$PathClients\$newName")) {
                    Write-Host -ForegroundColor Green "OK"
                    Write-Host -ForegroundColor Cyan "Renaming `"$ClientCode`" to `"$PathClients\$newName`" ... " -NoNewline
                    try {
                        $ClientCode | Rename-Item -NewName $newName -Force
                        Write-Host -ForegroundColor Green "OK"
                    } catch {
                        Write-Error $_.Exception.Message
                    }
                } else {
                    Write-Host -ForegroundColor Yellow "Warn: (exists)"
                } 
            }
        } else {Write-Host -ForegroundColor Gray "nope" }
    }

    # Archive part
    foreach ($ClientCode in (Get-ChildItem $PathArchive -Depth 0)) {
        $newName = $false
        Write-Host -ForegroundColor Gray "Checking if $($ClientCode.Name) is in CSV ... " -NoNewline
        if ($ClientCode.Name -in $CSV.ClientCode) {

            $newName = $CSV.Where({$PSItem.ClientCode -eq $ClientCode.Name}).EntityName

            Write-Host -ForegroundColor Green "found! New name would be `"$newName`""
            if($newName -and $newName.Length -ge 1) {
                Write-Host -ForegroundColor Gray "Checking if `"$PathArchive\$newName`" not exists ... " -NoNewline
                if (-not (Test-Path "$PathArchive\$newName")) {
                    Write-Host -ForegroundColor Green "OK"
                    Write-Host -ForegroundColor Cyan "Renaming `"$ClientCode`" to `"$PathArchive\$newName`" ... " -NoNewline
                    try {
                        $ClientCode | Rename-Item -NewName $newName -Force
                        Write-Host -ForegroundColor Green "OK"
                    } catch {
                        Write-Error $_.Exception.Message
                    }
                } else {
                    Write-Host -ForegroundColor Yellow "Warn: (exists)"
                } 
            }
        } else {Write-Host -ForegroundColor Gray "nope" }
    }
}


###--- END EXECUTION ---###
END
{
    Write-Host ("--------")
}
