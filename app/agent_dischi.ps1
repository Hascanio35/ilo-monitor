<#
  iLO Monitor - dischi di questo server: stato SMART e vita residua

  Server nel pannello : {{NOME}}
  Pannello            : {{URL}}
  Generato il         : {{DATA}}

  Legge da Windows i dischi fisici (NVMe compresi) con i contatori SMART
  - usura, temperatura, ore di accensione, errori - e li invia al
  pannello. La chiave qui sotto vale solo per questo server: generando
  un nuovo script dal pannello, questa smette di funzionare.

  INSTALLAZIONE (una volta, da PowerShell aperto come amministratore):

      powershell -ExecutionPolicy Bypass -File .\{{FILE}} -Installa

  Copia lo script in C:\ProgramData\iLO-Monitor, crea l'attivita'
  pianificata "iLO Monitor - dischi" (ogni ora e all'avvio, come SYSTEM)
  e invia subito i dati.

  Altri usi:
      .\{{FILE}} -Mostra     mostra i dischi letti, senza inviare nulla
      .\{{FILE}} -Rimuovi    toglie l'attivita' pianificata

  Requisiti: Windows Server 2012 o successivo (PowerShell 4+).
  L'ultimo esito si trova in C:\ProgramData\iLO-Monitor\ultimo-invio.log
#>
param([switch]$Installa, [switch]$Rimuovi, [switch]$Mostra)

$Pannello     = '{{URL}}'
$Chiave       = '{{TOKEN}}'
$NomeAttivita = 'iLO Monitor - dischi'
$Cartella     = Join-Path $env:ProgramData 'iLO-Monitor'
$FileLog      = Join-Path $Cartella 'ultimo-invio.log'

$ErrorActionPreference = 'Stop'

# Alcune versioni di Windows restituiscono i codici numerici invece dei
# nomi: li traduciamo qui, cosi' il pannello riceve sempre testo.
$TipiBus = @{0='Unknown';1='SCSI';2='ATAPI';3='ATA';4='1394';5='SSA';
    6='Fibre Channel';7='USB';8='RAID';9='iSCSI';10='SAS';11='SATA';12='SD';
    13='MMC';14='Virtual';15='File Backed Virtual';16='Storage Spaces';
    17='NVMe';18='SCM';19='UFS'}
$TipiSupporto = @{0='Unspecified';3='HDD';4='SSD';5='SCM'}
$Salute = @{0='Healthy';1='Warning';2='Unhealthy';5='Unknown'}

# ------------------------------------------------------------------
# Lettura diretta dei registri SMART
# ------------------------------------------------------------------
# I contatori che Windows espone (Get-StorageReliabilityCounter) sono
# spesso vuoti o a zero: l'usura degli SSD SATA non la conosce quasi
# mai, e su alcuni NVMe manca perfino il conteggio delle ore. Qui si
# leggono i dati alla fonte:
#  - NVMe: registro "SMART / Health Information" e dati di
#    identificazione, con la stessa richiesta che usa Windows stesso
#    (IOCTL_STORAGE_QUERY_PROPERTY, Windows 10 / Server 2016 o successivi);
#  - SATA: attributi SMART dal provider WMI del driver di disco.
# L'interpretazione dei valori la fa il pannello: se un produttore usa
# un attributo diverso si corregge li', senza reinstallare lo script.

$CodiceNvme = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class IloMonitorNvme2 {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
        byte[] inBuffer, int inSize, byte[] outBuffer, int outSize,
        out int returned, IntPtr overlapped);

    // property: 49 = adattatore (dati del controller, per Identify),
    //           50 = dispositivo (registri di salute).
    // dataType: 1 = Identify, 2 = Log page. value: CNS o numero del log.
    public static byte[] Query(int disk, int property, int dataType, int value, int length) {
        using (SafeFileHandle h = CreateFile("\\\\.\\PhysicalDrive" + disk,
                0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (h.IsInvalid) return null;
            byte[] buf = new byte[8 + 40 + length];
            BitConverter.GetBytes(property).CopyTo(buf, 0);
            BitConverter.GetBytes(0).CopyTo(buf, 4);       // PropertyStandardQuery
            BitConverter.GetBytes(3).CopyTo(buf, 8);       // ProtocolTypeNvme
            BitConverter.GetBytes(dataType).CopyTo(buf, 12);
            BitConverter.GetBytes(value).CopyTo(buf, 16);
            BitConverter.GetBytes(0).CopyTo(buf, 20);
            BitConverter.GetBytes(40).CopyTo(buf, 24);     // ProtocolDataOffset
            BitConverter.GetBytes(length).CopyTo(buf, 28); // ProtocolDataLength
            int returned;
            if (!DeviceIoControl(h, 0x2D1400, buf, buf.Length, buf, buf.Length,
                    out returned, IntPtr.Zero)) return null;
            int offset = BitConverter.ToInt32(buf, 24);
            int size = BitConverter.ToInt32(buf, 28);
            if (size <= 0 || 8 + offset + size > buf.Length) return null;
            byte[] data = new byte[size];
            Array.Copy(buf, 8 + offset, data, 0, size);
            return data;
        }
    }
}
'@

$NvmeDisponibile = $false
try {
    if (-not ('IloMonitorNvme2' -as [type])) {
        Add-Type -TypeDefinition $CodiceNvme -Language CSharp -ErrorAction Stop
    }
    $NvmeDisponibile = $true
} catch { }

function Testo-Ascii([byte[]]$dati, [int]$da, [int]$quanti) {
    # Solo caratteri stampabili: altrimenti la lettura non e' quella
    # giusta e meglio non usarla.
    for ($i = $da; $i -lt $da + $quanti; $i++) {
        if ($dati[$i] -ne 0 -and ($dati[$i] -lt 32 -or $dati[$i] -gt 126)) { return $null }
    }
    $testo = ([Text.Encoding]::ASCII.GetString($dati, $da, $quanti)).Trim([char]0, ' ')
    if ($testo) { return $testo }
    return $null
}

function Leggi-Nvme($numeroDisco) {
    if (-not $NvmeDisponibile) { return $null }
    $esito = [ordered]@{}
    try {
        $id = [IloMonitorNvme2]::Query([int]$numeroDisco, 49, 1, 1, 4096)
        if ($id) {
            $sn = Testo-Ascii $id 4 20
            if ($sn) { $esito.seriale = $sn }
            $mn = Testo-Ascii $id 24 40
            if ($mn) { $esito.modello = $mn }
            $fw = Testo-Ascii $id 64 8
            if ($fw) { $esito.firmware = $fw }
        }
    } catch { }
    try {
        $h = [IloMonitorNvme2]::Query([int]$numeroDisco, 50, 2, 2, 512)
        if ($h) {
            $esito.avviso_critico      = [int]$h[0]
            $esito.temperatura_kelvin  = [int][BitConverter]::ToUInt16($h, 1)
            $esito.riserva             = [int]$h[3]
            $esito.riserva_soglia      = [int]$h[4]
            $esito.percentuale_usata   = [int]$h[5]
            $esito.unita_lette         = [BitConverter]::ToUInt64($h, 32)
            $esito.unita_scritte       = [BitConverter]::ToUInt64($h, 48)
            $esito.cicli_accensione    = [BitConverter]::ToUInt64($h, 112)
            $esito.ore_accensione      = [BitConverter]::ToUInt64($h, 128)
            $esito.spegnimenti_anomali = [BitConverter]::ToUInt64($h, 144)
            $esito.errori_supporto     = [BitConverter]::ToUInt64($h, 160)
            $esito.voci_registro_errori = [BitConverter]::ToUInt64($h, 176)
        }
    } catch { }
    if ($esito.Count -eq 0) { return $null }
    return $esito
}

# Attributi SMART dei dischi ATA/SATA, letti una volta per tutti i dischi.
$SmartAta = @()
$PrevisioneAta = @()
try { $SmartAta = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_ATAPISmartData -ErrorAction Stop) } catch { }
try { $PrevisioneAta = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop) } catch { }
$AtaUsati = @{}

function Chiave-Testo($testo) {
    return (("$testo").ToUpper() -replace '[^A-Z0-9]', '')
}

function Trova-Ata($modello) {
    # Il nome dell'istanza contiene il modello con i caratteri speciali
    # sostituiti: si confrontano solo lettere e cifre.
    $chiave = Chiave-Testo $modello
    if ($chiave.Length -lt 6) { return $null }
    foreach ($s in $SmartAta) {
        if ($AtaUsati.ContainsKey($s.InstanceName)) { continue }
        if ((Chiave-Testo $s.InstanceName).Contains($chiave)) {
            $AtaUsati[$s.InstanceName] = $true
            return $s
        }
    }
    return $null
}

function Attributi-Ata($istanza) {
    $v = [byte[]]$istanza.VendorSpecific
    $attributi = @()
    for ($i = 0; $i -lt 30; $i++) {
        $base = 2 + $i * 12
        if ($base + 11 -ge $v.Length) { break }
        $codice = [int]$v[$base]
        if ($codice -eq 0) { continue }
        $grezzo = [uint64]0
        for ($b = 5; $b -ge 0; $b--) { $grezzo = $grezzo * 256 + $v[$base + 5 + $b] }
        $attributi += New-Object PSObject -Property ([ordered]@{
            id = $codice; valore = [int]$v[$base + 3]; peggiore = [int]$v[$base + 4]; grezzo = $grezzo
        })
    }
    return ,$attributi
}

function Previsione-Ata($istanza) {
    foreach ($p in $PrevisioneAta) {
        if ($p.InstanceName -eq $istanza.InstanceName) { return [bool]$p.PredictFailure }
    }
    return $null
}

function Nome-Codice($valore, $mappa) {
    if ($null -eq $valore) { return $null }
    $testo = "$valore"
    if ($testo -match '^\d+$' -and $mappa.ContainsKey([int]$testo)) {
        return $mappa[[int]$testo]
    }
    return $testo
}

function Valore($oggetto, $nome) {
    if ($null -eq $oggetto) { return $null }
    return $oggetto.$nome
}

function Leggi-Dischi {
    $esito = @()
    foreach ($d in Get-PhysicalDisk) {
        $bus = Nome-Codice $d.BusType $TipiBus
        $modello = ("$($d.Model)").Trim()
        if (-not $modello) { $modello = ("$($d.FriendlyName)").Trim() }

        # I volumi dei controller RAID (Smart Array, S100i), le chiavette
        # e i dischi virtuali non sono dischi fisici: quelli dietro al
        # RAID li legge gia' l'iLO.
        # Anche i volumi iSCSI e Fibre Channel sono dischi di rete, non del server.
        if (@('RAID','USB','Virtual','File Backed Virtual','Storage Spaces','SD','MMC','iSCSI','Fibre Channel') -contains $bus) { continue }
        if ($modello -match 'LOGICAL VOLUME|Virtual Disk|Msft Virtual') { continue }

        $c = $null
        try { $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }

        $nvme = $null
        $ata = $null
        $previsione = $null
        if ($bus -eq 'NVMe') {
            $nvme = Leggi-Nvme $d.DeviceId
        } elseif (@('ATA','SATA') -contains $bus) {
            $istanza = Trova-Ata $modello
            if ($istanza) {
                $ata = Attributi-Ata $istanza
                $previsione = Previsione-Ata $istanza
            }
        }
        # Su molti NVMe Windows mostra come seriale l'identificativo EUI
        # ("0026_B768_..."): quello vero sta nei dati di identificazione.
        $seriale = ("$($d.SerialNumber)").Trim().TrimEnd('.')
        $serialeAdattatore = ("$($d.AdapterSerialNumber)").Trim()
        if ($nvme -and $nvme.seriale) { $seriale = $nvme.seriale }
        elseif ($serialeAdattatore -and $serialeAdattatore -notmatch '[^\x20-\x7E]' -and $seriale -match '_') {
            $seriale = $serialeAdattatore
        }

        $esito += New-Object PSObject -Property ([ordered]@{
            numero                    = "$($d.DeviceId)"
            modello                   = $modello
            seriale                   = $seriale
            firmware                  = ("$($d.FirmwareVersion)").Trim()
            bus                       = $bus
            tipo                      = Nome-Codice $d.MediaType $TipiSupporto
            dimensione                = [int64]$d.Size
            giri                      = $d.SpindleSpeed
            salute                    = Nome-Codice $d.HealthStatus $Salute
            posizione                 = "$($d.PhysicalLocation)"
            usura                     = Valore $c 'Wear'
            temperatura               = Valore $c 'Temperature'
            temperatura_max           = Valore $c 'TemperatureMax'
            ore_accensione            = Valore $c 'PowerOnHours'
            cicli_accensione          = Valore $c 'StartStopCycleCount'
            errori_lettura            = Valore $c 'ReadErrorsUncorrected'
            errori_scrittura          = Valore $c 'WriteErrorsUncorrected'
            errori_lettura_corretti   = Valore $c 'ReadErrorsCorrected'
            errori_scrittura_corretti = Valore $c 'WriteErrorsCorrected'
            latenza_lettura_max_ms    = Valore $c 'ReadLatencyMax'
            latenza_scrittura_max_ms  = Valore $c 'WriteLatencyMax'
            nvme                      = $nvme
            ata                       = $ata
            previsione_guasto         = $previsione
        })
    }
    return ,$esito
}

function Scrivi-Log($testo) {
    try {
        New-Item -ItemType Directory -Force -Path $Cartella | Out-Null
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $testo" | Out-File -FilePath $FileLog -Encoding UTF8
    } catch { }
}

# ---------------------------------------------------------------- rimozione
if ($Rimuovi) {
    Unregister-ScheduledTask -TaskName $NomeAttivita -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Attivita' pianificata '$NomeAttivita' rimossa."
    return
}

# ---------------------------------------------------------------- installazione
if ($Installa) {
    $identita = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identita.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Serve PowerShell aperto come amministratore." -ForegroundColor Red
        exit 1
    }
    New-Item -ItemType Directory -Force -Path $Cartella | Out-Null
    $destinazione = Join-Path $Cartella 'dischi.ps1'
    if ($PSCommandPath -ne $destinazione) {
        Copy-Item -Path $PSCommandPath -Destination $destinazione -Force
    }
    $azione = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$destinazione`""
    $ogniOra = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
        -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    $avvio = New-ScheduledTaskTrigger -AtStartup
    $utente = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $impostazioni = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $NomeAttivita -Action $azione `
        -Trigger @($ogniOra, $avvio) -Principal $utente -Settings $impostazioni -Force | Out-Null
    Write-Host "Attivita' pianificata '$NomeAttivita' creata: invio ogni ora e all'avvio."
    Write-Host "Script installato in $destinazione"
}

# ---------------------------------------------------------------- lettura e invio
try {
    $dischi = Leggi-Dischi
} catch {
    Scrivi-Log "ERRORE lettura dischi: $($_.Exception.Message)"
    Write-Host "Lettura dei dischi non riuscita: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($Mostra) {
    $dischi | Select-Object modello, seriale, bus, tipo, salute,
        @{n='usura NVMe %'; e={ if ($_.nvme) { $_.nvme.percentuale_usata } }},
        @{n='ore'; e={ if ($_.nvme) { $_.nvme.ore_accensione } else { $_.ore_accensione } }},
        @{n='anni'; e={ $o = if ($_.nvme) { $_.nvme.ore_accensione } else { $_.ore_accensione }; if ($o) { [math]::Round($o / 8760, 1) } }},
        @{n='attributi SMART'; e={ if ($_.ata) { $_.ata.Count } }} |
        Format-Table -AutoSize
    Write-Host "$($dischi.Count) dischi letti (nessun invio: modalita' -Mostra)."
    return
}

$corpo = @{
    host     = $env:COMPUTERNAME
    versione = 2
    dischi   = @($dischi)
} | ConvertTo-Json -Depth 6

try {
    $risposta = Invoke-RestMethod -Uri "$Pannello/api/agent/drives" -Method Post `
        -Body ([Text.Encoding]::UTF8.GetBytes($corpo)) `
        -ContentType 'application/json; charset=utf-8' `
        -Headers @{ Authorization = "Bearer $Chiave" } -TimeoutSec 60 -UseBasicParsing
    $messaggio = "OK: $($risposta.salvati) dischi inviati a $Pannello"
    Scrivi-Log $messaggio
    Write-Host $messaggio
} catch {
    $dettaglio = $_.Exception.Message
    try {
        $flusso = $_.Exception.Response.GetResponseStream()
        $dettaglio += " - " + (New-Object IO.StreamReader($flusso)).ReadToEnd()
    } catch { }
    Scrivi-Log "ERRORE invio: $dettaglio"
    Write-Host "Invio non riuscito: $dettaglio" -ForegroundColor Red
    exit 1
}
