Function POSH-Toruk
{

	##############################################################################
	#.SYNOPSIS
	# Retrieves data from Falcon Host API.
	#
	#.DESCRIPTION
	# Can retrieve alerts and systems with agents installed for all customers or by
	# instance ID.
	#
	#.PARAMETER QueryType
	# The data set to retrieve, either 'Alerts' or 'Systems'.
	#
	#.PARAMETER OutFile
	# Where to output results. If not set, results will be output to screen. 
	# In 'Systems' QueryType, output is in comma-separated value format.
	#
	#.PARAMETER LoopHours
	# Runs in loop for the amount of hours selected. Minimum 1, maximum 12.
	#
	#.PARAMETER FrequencyMinutes
	# Frequency in minutes for the next iteration of loop to begin. Minimum 0, maximum 5.
	#
	#.PARAMETER Instance
	# CID for specific customer instances. Results will include only this/these customer(s).
	# Comma separate CIDs for multiple instances. If null, all customers will be queried. 
	#
	#.PARAMETER ConfigFile
	# Configuration file storing Falcon Host credentials. Format is:
	# username,password
	# <insert username>,<insert password>
	#
	##############################################################################


	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
	param
	(
		[Parameter(ParameterSetName="p0",Position=1,Mandatory=$True)][ValidateSet("Alerts","Systems")]$QueryType,
		[Parameter(ParameterSetName="p0",Position=2)]$ConfigFile,
		[Parameter(ParameterSetName="p0",Position=3)][ValidateRange(1,12)]$LoopHours,
		[Parameter(ParameterSetName="p0",Position=4)][ValidateRange(0,5)]$FrequencyMinutes,
		[Parameter(ParameterSetName="p0",Position=5)]$Instance,
		[Parameter(ParameterSetName="p0",Position=6)]$OutFile
	)
		
	$Title = "

                 *************************************************
                     ____    _____   ____    __  __     
                    /\  _``\ /\  __``\/\  _``\ /\ \/\ \    
                    \ \ \L\ \ \ \/\ \ \,\L\_\ \ \_\ \   
                     \ \ ,__/\ \ \ \ \/_\__ \\ \  _  \  
                      \ \ \/  \ \ \_\ \/\ \L\ \ \ \ \ \ 
                       \ \_\   \ \_____\ ``\____\ \_\ \_\
                        \/_/    \/_____/\/_____/\/_/\/_/  
                      ______  _____   ____    __  __  __  __    
                     /\__  _\/\  __``\/\  _``\ /\ \/\ \/\ \/\ \      
                     \/_/\ \/\ \ \/\ \ \ \L\ \ \ \ \ \ \ \/'/' 
                        \ \ \ \ \ \ \ \ \ ,  /\ \ \ \ \ \ , < 
                         \ \ \ \ \ \_\ \ \ \\ \\ \ \_\ \ \ \\``\ 
                          \ \_\ \ \_____\ \_\ \_\ \_____\ \_\ \_\ 
                           \/_/  \/_____/\/_/\/ /\/_____/\/_/\/_/ 
                         
                 
                      **** F a l c o n  T o o l  S u i t e ****			
                  *************************************************"

	$Art = "
                                                                                             ``/``
                                                                                           -/-.
                                                                                        ``:o+.:
                                                                                      ``+s.+/o
                                                                                     /hs+s/d``
     .                                                                            ``/o+``so/--
     --   ``:                                                                    -oy- +++ s/
      +-   +.                                                                ``:osooo+o/+``h``            ``
      -+-`` ./``                                                             -/oo+/++++sdso-         .:+y-
       +ss. +/``                                                         ``/ssso++++oyho:``      ``--:s///``
       ``hmm-.o:                                                       .oyssso++oss+-``  ``.-/+soo:os//``
        ``omd.+h:                                                    .oyysssyys+:...:+ossoo++s/::oo.
         ``+dh-dm. .                                     ````        -syyyyso/--:+oyyyyso++///+s+:y:
          ``ody/No``/.                                    ``.-:    -shysoo/+osyyyssssossssssooss+-``
           ``odsyy os-                                      /s``-oyysssyyhhhyyyssoo+++/:-.....---..:--/:
            ``odyh``yNm-                                    -hNhhhysoosso/::::::::://///+osyy-/++:od+/-``
             ``odyo+mm+                               ``:+sdmNNmmdhhyyyyssssssssoooo++++++oh/-/oo+:.``
              ``ohdmmd.                             ``sddhdddhyhhhhhddddhsoo+ooooo++oooooosh+:-.``
               ``+hmd++ooyyo        .              ``oNmdddyyysssssssysyyhddddddhyysso+///:-.
               .:+shdmmmmmm``   ``.:os.             /dNmddhhyyyyyssssossssssyyyyyhhhyyhhhdmd-
               +- ``:yNdmmmN+:+:::::.            ``+hmmmmdddddhyyyssssssssssssssssssssoosyh-
               .    .sddmmNh+``                 .odNNmmmddddddddhhyyyysssssssssssssooooyh.
                     ``ohmdmmh``                .smmNmmmmmddhdddhhhhhhhysssssssoooooooshs.
                    ``:-oddmdNh``             ``/ymdmNmddddhyysyyhhyyyyyhhhyssssooooooyy/``
                   ./:sysyyhdmy.          ./hmdmmNmddhhhhhyysssyyhhysssyhhhysooosys:``
                  ``shNdmmmmmmmhs-``     ``-oydmmmNNmdddhhhhhhyyyysssyyyysssssyyhyyo-
               .:sdmdddysosyddmmdo+++osydddmNmmNmmdddddhyyyyhyyssssssyhyyyyyo/-``
       ````.-:/+sdNmNms:..`` ````:sdmmmmNNNmmmmmNNNNmdddddhhdhhyyyyyyysyyyyyho:-``
     .--:/+sydNdhyNs``        /ddhhyhdhdmmNNNNmddmmddhhyyhhhhyyyhyys+-.``
      ``-/oshNNmdddNs-        sydhhmyhdysydmmmdddddyyyyhhyhddhyo/.``
       ``/hmNmmoshMmy+``       /yhhhhhhdhysyhdddhhdhysssossshs:``
         /o/-. smNhs+:       /myhhddmdhyhyyyhhhyyssooooossssso:.
              .dNhs+/:. ``/+:-:dhdhdmddhyssyyssysooooooooosssssss-
              ``++:-.``..``/hhddhhdhymmdddhssoo+/++oooooooosso/-.``
                       ``ohydddhdhmNhhhdhhhho+///++oooos+-``
                        +hyd-/shyydddmddhhhyso+/++ooso.
                        .yyh  ``+ydddhhhhhhdhyyso+ooys
                   -/.   :hy .sddhsoyhhhhhhdhhhysosh.
                 ``///oo`` ``sy``smdh+  ./ssyyyhhhhhysoy
                    ``+my-``+d.hdhy.    ``/syyyyyyyyssy-
                      .hhyhh-hdy-       .syyhhyyyyyys
                       ``o   -dh.         .ohhhhoyhyyy/
                        ``   .ds            /yhh-``:oyyy:
                            -do             ``ohh-  -osy+``
                          ``:yh:               -sh+``  ``:sy+``
                        ``/yd/                   :yho.   -oy+``
                       :shd/                      -+y+.   ``:s+:``
                     .++.y o:                        -oo-``   ``:o+.
                     +- s-  /                           -+/.    ``:+:
                        ````                                 .//-    ./:
                                                              .::.   ``-"
															  
	Write-Host "$Art`n" -ForegroundColor Red
	Write-Host "$Title`n`n"
	If ($LoopHours)
	{
		Out-FalconPrint "Informational" "Loop mode selected"
		Out-FalconPrint "Informational" "Running in a loop for $LoopHours hour(s)"
		$TimeOut = (Get-Date).AddHours($LoopHours)
		If ($OutFile)
		{
			Out-FalconPrint "Informational" "It is not advisable to output to a file while in loop mode. Contents will be overwritten each iteration."
		}
		While ($(Get-Date) -lt $Timeout)
		{
			Get-FalconAuth
			If (!$FrequencyMinutes)
			{
				$FrequencyMinutes = 1
			}
			Out-FalconPrint "Informational" "Sleeping for $FrequencyMinutes minute(s)"
			Start-Sleep -Seconds ($FrequencyMinutes * 60)
		}
	}
	Else
	{
		Get-FalconAuth
	}
}

Function Get-FalconAuth
{
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12		
	$Headers = @{
				'Accept'="application/json, text/javascript, */*; q=0.01";
				'Accept-Encoding'="gzip, deflate, br";
				'Accept-Language'="en-US; q=0.7, en; q=0.3";
				'Cache-Control'="no-cache";
				'Content-Type'="application/json";
				'X-Requested-With'="XMLHttpRequest"
				}
					
	$Response0 = Invoke-WebRequest -Method GET -Uri https://falcon.crowdstrike.com/auth/login -Headers $headers -SessionVariable FaH
	$Response1 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/auth/csrf -Headers $headers -WebSession $FaH
	$Headers.Add('X-CSRF-TOKEN', ($Response1.content | ConvertFrom-Json).csrf_token)

	$Username,$DPassword = Set-FalconAuth
	Out-FalconPrint "Prompt"
	$2FA = Read-Host -Prompt "Enter FH 2FA"
	
	Try
	{
		$Auth_Data = [ordered]@{
					  'username' = $UserName;
					  'password' = $DPassword;
					  '2fa' = $2FA
					  }
		$JsonAuth_Data = $Auth_Data | ConvertTo-Json
		$Response2 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/auth/login -Headers $headers -Body $JsonAuth_Data -WebSession $FaH
		$Response3 = Invoke-WebRequest -Method GET -Uri https://falcon.crowdstrike.com/ -WebSession $FaH
		$Response4 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/auth/verify -Headers $Headers -WebSession $FaH
	}
	Catch [Exception]
	{
		If (($_.ErrorDetails.Message -like "*InvalidCredentials*") -or 
			($_.ErrorDetails.Message -like "*InvalidMFA*") -or
			($_.ErrorDetails.Message -like "*Failed user login*") -or
			($_.ErrorDetails.Message -like "*Missing username*")) 
		{
			Out-FalconPrint "Alert" "Invalid Falcon Host Credentials."
			Return
		}
		Else
		{
			Out-FalconPrint "Alert" "$($_.Exception.Message)"
			Return
		}
	}
	$Headers."X-CSRF-TOKEN" = ($Response4.content | ConvertFrom-Json).csrf_token
	If ($Instance)
	{
		$FalconIDs = @()
		Foreach ($FalconID in $($Instance.split(",")))
		{
			If ($($Response4.content | ConvertFrom-Json).customers -contains $FalconID)
			{
				$FalconIDs += $FalconID
			}
			Else
			{
				Out-FalconPrint "Alert" "One or more invalid Falcon Host CID(s)."
				Return
			}
		}
	}
	Else
	{
		$Exclusions = #define any exclusions here
		$If ($Exlcusions)
		{
			Out-FalconPrint "Informational" "Excluding following from query:"
			Foreach ($Exclusion in $Exclusions)
			{
				Out-FalconPrint "Informational" "`t- $($($Response4.content | ConvertFrom-Json).user_customers.$Exclusion.name)"
			}
			$FalconIds = ($Response4.content | ConvertFrom-Json).customers | %{$_ | Where-Object {$Exclusions -notcontains $_}}
		}
	}
	
	

	Switch($QueryType)
	{
		"Alerts" {Get-FalconAlerts}
		"Systems" {Get-FalconSystems}
	}
}

Function Set-FalconAuth
{
	If ($ConfigFile)
	{
		Try
		{
			$UserName = Import-Csv -Path $ConfigFile | %{$_.username}
			$SecurePassword = Import-Csv -Path $ConfigFile | %{$_.password} | ConvertTo-SecureString -AsPlainText -Force
			$DPassword = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($SecurePassword))
			Out-FalconPrint "Informational" "Credentials read from config file"
		}
		Catch [Exception]
		{
			Out-FalconPrint "Alert" "Check your config file and rerun the program, exiting..."
			Out-FalconPrint "Alert" "$($_.Exception.Message)"
			Return
		}
	}
	Else
	{
		Out-FalconPrint "Prompt"
		$UserName = Read-Host -Prompt "Enter FH Username (email address)"
		Out-FalconPrint "Prompt"
		$Password = Read-Host -Prompt "Enter FH Password" -AsSecureString
		$SecurePassword = New-Object System.Net.NetworkCredential($null, $Password, $null)
		$DPassword = $SecurePassword.Password
	}
	Return $Username, $DPassword
}

Function Get-FalconAlerts
{
	$count = 0
	$FirstFlag = $False
	$FalconIdsCount = $FalconIds.count
	
	Out-FalconPrint "Informational" "$($FalconIdsCount) customer instances detected"
	Out-FalconPrint "Informational" "Performing search ($(Get-Date -Format HH:mm:ssL))..."
	Foreach ($FalconId in $FalconIds)
	{	
		$count++
		$CustomerName = ($Response4.content | ConvertFrom-Json).user_customers.$FalconId.name
		Write-Progress -Activity 'Processing Customers' -Status "$count of $($FalconIdscount)" -CurrentOperation $CustomerName -PercentComplete ($count/$($FalconIdscount) * 100)
		$body1 = (@{'cid' = $FalconId}) | ConvertTo-Json
		$Response5 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/auth/switch-customer -Headers $Headers -body $body1 -WebSession $FaH
		Try
		{
			$Response11 = Invoke-WebRequest -Method GET -Uri "https://falcon.crowdstrike.com/api2/detects/queries/detects/v1?filter=status%3A%27new%27" -Headers $Headers -WebSession $FaH
		}
		Catch
		{
			Out-FalconPrint "Alert" "Unable to pull information for $CustomerName"
			Continue
		}
		$Ldt = ($Response11.content | ConvertFrom-Json).resources
		If ($Ldt -ne $Null)
		{
			$body2 = (@{"ids" = $Ldt}) | ConvertTo-Json
			$Response12 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/detects/entities/summaries/GET/v1 -Headers $Headers -Body $body2 -WebSession $FaH
			$InfoArray = @()
			Foreach ($Resource in (($Response12.content | ConvertFrom-Json).resources))
			{
				$InfoArray += "`t- $($Resource.max_severity_displayname) severity $($Resource.behaviors.scenario)"
				$InfoArray += "`t`tUsername: $($Resource.behaviors.user_name)"
				$InfoArray += "`t`tCommandLine: $($Resource.behaviors.cmdline)"
				$InfoArray += "`t`tFileName: $($Resource.behaviors.filename)"
				$InfoArray += "`t`tSHA256: $($Resource.behaviors.sha256)"
				$InfoArray += "`t`tMD5: $($Resource.behaviors.md5)"
				$InfoArray += "`t`tHostname: $($Resource.device.hostname)"
				$InfoArray += "`t`tDeviceID: $($Resource.behaviors.device_id)"
				$InfoArray += "`t`tOS: $($Resource.device.os_version)"
				$InfoArray += "`t`tAlertID: $($($Resource.detection_id).replace('ldt:',''))"
			}
			If ($OutFile -eq $Null)
			{
				Write-Host "`n$CustomerName"
				Write-Host ("*" * $CustomerName.length)
				Out-FalconPrint "Informational" "$($Ldt.count) alert(s) detected!"
				$InfoArray | %{Out-FalconPrint "Informational" $_}
			}
			Else
			{
				Try
				{
					If ($FirstFlag -eq $False) 
					{	
						$FirstFlag = $True
						If ((Test-Path -Path $OutFile) -eq $True)
						{
							Clear-Content -Path $OutFile
						}
						Write-Output "Total instances: $($FalconIds.count)" | Out-File -FilePath $OutFile -Append
						Write-Output "Report generated by: $UserName" | Out-File -FilePath $OutFile -Append
						Write-Output "Report powered by: POSH-Toruk" | Out-File -FilePath $OutFile -Append
						Write-Output ((Get-Date).ToString()) | Out-File -FilePath $OutFile -Append
						Write-Output ("=" * 75) | Out-File -FilePath $OutFile -Append
						Out-FalconPrint "Informational" "Writing contents to $((Get-Item -Path $OutFile).FullName)"
					}
					Write-Output "`n$CustomerName" | Out-File -FilePath $OutFile -Append
					Write-Output ("*" * $CustomerName.length) | Out-File -FilePath $OutFile -Append
					Write-Output "[!] $($Ldt.count) alert(s) detected!" | Out-File -FilePath $OutFile -Append
					$InfoArray | %{Write-Output "Informational $($_)" | Out-File -FilePath $OutFile -Append}
				}
				Catch [Exception]
				{
					Out-FalconPrint "Alert" "Error in outputting to file at $((Get-Item -Path $OutFile).FullName)" 
					Out-FalconPrint "Alert" "$($_.Exception.Message)"
					Return
				}
			}
		}
	}
	Out-FalconPrint "Informational" "Search complete ($(Get-Date -Format HH:mm:ssL))...`n"
}

Function Get-FalconSystems
{
	$FalconIdsCount = $FalconIds.count
	Out-FalconPrint "Informational" "$($FalconIdsCount) customer instances detected"
	Out-FalconPrint "Informational" "Performing search ($(Get-Date -Format HH:mm:ssL))..."
	
	$CollectionArray = @()
	$count = 1
	
	Foreach ($FalconId in $FalconIds)
	{	
		$CustomerName = ($Response4.content | ConvertFrom-Json).user_customers.$FalconId.name
		Write-Progress -Activity 'Processing Customers' -Status "$count of $($FalconIdsCount)" -CurrentOperation $CustomerName -PercentComplete ($count/$($FalconIdsCount) * 100)
		$body1 = (@{'cid' = $FalconId}) | ConvertTo-Json
		$Response5 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/auth/switch-customer -Headers $Headers -body $body1 -WebSession $FaH
		$Response6 = Invoke-WebRequest -Method POST -Uri https://falcon.crowdstrike.com/api2/auth/verify -Headers $Headers -WebSession $FaH
		$headers."X-CSRF-TOKEN" = ($Response6.content | ConvertFrom-Json).csrf_token
		
		$Response8 = Invoke-WebRequest -Method GET -Uri https://falcon.crowdstrike.com/api2/devices/queries/devices/v1?sort=last_seen.desc -WebSession $FaH -Headers $headers
		$Aids = ($Response8.content | ConvertFrom-Json).resources
		$URI = "https://falcon.crowdstrike.com/api2/devices/entities/devices/v1?" 
		Foreach ($Aid in $Aids)
		{
			$URI += "ids=$Aid&"
		}
		$URI = $URI -replace "&$"
		Try
		{
			$Response9 = Invoke-WebRequest -Method GET -Uri $URI -WebSession $FaH -Headers $headers
		}
		Catch [Exception]
		{
			#duplicate keys or null value
		}
		$MachineInfo = ($Response9.content | ConvertFrom-Json).resources

		Foreach ($Machine in $MachineInfo)
		{
			$FalconID = $Machine.cid
			$CustomerName = ($Response4.content | ConvertFrom-Json).user_customers.$FalconId.name
			$CollectionArray += New-Object PsObject -Property @{
				'Customer' = $CustomerName
				'Hostname' = $Machine.hostname
				'Operating System' = $Machine.os_version
				'Public IP' = $Machine.external_ip
				'Last Seen' = $Machine.last_seen
			}
		}
		$count++
	}
	If ($OutFile)
	{
		Try
		{
			Out-FalconPrint "Informational" "Writing contents to $((Get-Item -Path $OutFile).FullName)"
			$CollectionArray | Select-Object -Property "Customer", "Hostname", "Operating System", "Public IP", "Last Seen" | Export-Csv -Path $OutFile -NoTypeInformation
		}
		Catch [Exception]
		{
			Out-FalconPrint "Alert" "Error in outputting to file at $((Get-Item -Path $OutFile).FullName)" 
			Out-FalconPrint "Alert" "$($_.Exception.Message)"
		}
	}
	Else
	{
		$CollectionArray | Format-Table -Property "Hostname", "Operating System", "Public IP", "Last Seen" -GroupBy "Customer"
	}
	Out-FalconPrint "Informational" "Search complete ($(Get-Date -Format HH:mm:ssL))...`n"
}

Function Out-FalconPrint
{
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
	param
	(
		[Parameter(ParameterSetName="p0",Mandatory=$True,Position=1)][ValidateSet("Alert","Informational","Prompt")]$PrintType,
		[Parameter(ParameterSetName="p0",Position=2)]$PrintMessage
	)
	
	If ($PrintType -eq "Informational")
	{
		Write-Host "[" -NoNewLine
		Write-Host "*" -NoNewLine -ForegroundColor "Cyan"
		Write-Host "] $PrintMessage" 
		Return
	}
	ElseIf ($PrintType -eq "Prompt")
	{
		Write-Host "[" -NoNewLine
		Write-Host "$" -NoNewLine -ForegroundColor "Yellow"
		Write-Host "] " -NoNewLine
		Return
	}
	ElseIf ($PrintType -eq "Alert")
	{
		Write-Host "[" -NoNewLine
		Write-Host "!" -NoNewLine -ForegroundColor "Red"
		Write-Host "] $PrintMessage" 
		Return
	}
}
