<#
  iLO Monitor - dischi (e sensori) di questo server

  Server nel pannello : {{NOME}}
  Pannello            : {{URL}}
  Generato il         : {{DATA}}

  Legge da Windows i dischi fisici (NVMe compresi) con i contatori SMART
  - usura, temperatura, ore di accensione, errori - e li invia al
  pannello. La chiave qui sotto vale solo per questo server: generando
  un nuovo script dal pannello, questa smette di funzionare.

  Per i server la cui scheda di gestione non legge i sensori (per
  esempio una scheda IPMI su scheda madre non supportata) lo script
  invia anche temperature, ventole e carico, letti con
  LibreHardwareMonitor: vedi SENSORI piu' sotto.

  INSTALLAZIONE (una volta, da PowerShell aperto come amministratore):

      powershell -ExecutionPolicy Bypass -File .\{{FILE}} -Installa

  Copia lo script in C:\ProgramData\iLO-Monitor, crea l'attivita'
  pianificata "iLO Monitor - dischi" (come SYSTEM, all'avvio e ogni ora;
  ogni 5 minuti se invia anche i sensori) e invia subito i dati.

  Altri usi:
      .\{{FILE}} -Mostra     mostra cosa legge, senza inviare nulla
      .\{{FILE}} -Rimuovi    toglie l'attivita' pianificata

  SENSORI (solo se il pannello li chiede per questo server)
      Le temperature si leggono con la libreria di LibreHardwareMonitor,
      che -Installa scarica da sola da nuget.org (versione per .NET
      Framework) in C:\ProgramData\iLO-Monitor\lhm-<data>. Serve in piu' il
      driver PawnIO, che legge CPU e scheda madre; se manca:
          winget install namazso.PawnIO
      oppure avviando una volta LibreHardwareMonitor come amministratore
      e accettando l'installazione proposta.

  Requisiti: Windows Server 2012 o successivo (PowerShell 4+).
  L'ultimo esito si trova in C:\ProgramData\iLO-Monitor\ultimo-invio.log
#>
param([switch]$Installa, [switch]$Rimuovi, [switch]$Mostra, [string]$Lhm)

$Pannello     = '{{URL}}'
$Chiave       = '{{TOKEN}}'
$InviaSensori = ('{{SENSORI}}' -eq '1')
$NomeAttivita = 'iLO Monitor - dischi'
$Cartella     = Join-Path $env:ProgramData 'iLO-Monitor'
$FileLog      = Join-Path $Cartella 'ultimo-invio.log'
$FileDischi   = Join-Path $Cartella 'ultimo-invio-dischi.txt'
$CartellaLhm  = Join-Path $Cartella 'lhm'

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

# ------------------------------------------------------------------
# Sensori: temperature, ventole e carico con LibreHardwareMonitor
# ------------------------------------------------------------------

$CodiceRisolutore = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

public static class IloMonitorLhm2 {
    static string cartella;
    // Dictionary e non HashSet: sta in mscorlib, che Add-Type referenzia sempre.
    static readonly Dictionary<string, bool> inCorso = new Dictionary<string, bool>();
    // Le librerie di LibreHardwareMonitor chiedono versioni precise delle
    // loro dipendenze: senza un file .config PowerShell non le trova.
    // Si risponde con il file omonimo della cartella, qualunque versione
    // chieda; per le librerie di sistema (System.Management...) con
    // quella installata in Windows.
    public static void Registra(string percorso) {
        bool prima = cartella == null;
        cartella = percorso;
        if (!prima) return;
        AppDomain.CurrentDomain.AssemblyResolve += delegate(object s, ResolveEventArgs e) {
            string nome = new AssemblyName(e.Name).Name;
            string file = Path.Combine(cartella, nome + ".dll");
            if (File.Exists(file)) return Assembly.LoadFrom(file);
            if (!(nome.StartsWith("System.") || nome.StartsWith("Microsoft."))) return null;
            lock (inCorso) { if (inCorso.ContainsKey(nome)) return null; inCorso[nome] = true; }
            try {
#pragma warning disable 618
                return Assembly.LoadWithPartialName(nome);
#pragma warning restore 618
            } catch { return null; }
            finally { lock (inCorso) { inCorso.Remove(nome); } }
        };
    }
}
'@

# Cartelle lib dei pacchetti NuGet utilizzabili da .NET Framework 4.8,
# in ordine di preferenza.
$TfmUtili = @('net481','net48','net472','net471','net47','net462','net461','net46',
    'net452','net451','net45','net403','net40','net35','net20',
    'netstandard2.0','netstandard1.6','netstandard1.5','netstandard1.4',
    'netstandard1.3','netstandard1.2','netstandard1.1','netstandard1.0')
$Architettura = if ([Environment]::Is64BitProcess) { 'win-x64' } else { 'win-x86' }
# Gia' presenti in Windows: si usano quelle di sistema.
$PacchettiDiSistema = @('system.management','system.codedom','netstandard.library',
    'microsoft.netcore.platforms','microsoft.netcore.targets')

# Ogni installazione della libreria va in una cartella nuova
# (lhm-<data>): una libreria gia' caricata da un altro PowerShell aperto
# non si puo' cancellare ne' sovrascrivere finche' quello non si chiude.
function Cartella-Lhm-Attiva {
    $c = Get-ChildItem -Path $Cartella -Directory -Filter 'lhm-*' -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path (Join-Path $_.FullName 'LibreHardwareMonitorLib.dll')) -and
                       (Test-Path (Join-Path $_.FullName 'nuget.txt')) } |
        Sort-Object Name | Select-Object -Last 1
    if ($c) { return $c.FullName }
    return $null
}

function Lhm-Pronto {
    return [bool](Cartella-Lhm-Attiva)
}

function Tfm-Breve($tfm) {
    $t = "$tfm".Trim().ToLower()
    if ($t -match '^\.netframework(\d)\.(\d)(?:\.(\d))?$') { return 'net' + $matches[1] + $matches[2] + $matches[3] }
    if ($t -match '^\.netstandard(\d+\.\d+)$') { return 'netstandard' + $matches[1] }
    return $t
}

function Versione-Minima($intervallo) {
    $v = ("$intervallo".Trim().TrimStart('[', '(').Split(',')[0]).Trim().TrimEnd(']', ')').Trim()
    if ($v -match '^\d+\.\d+$') { $v += '.0' }
    return $v.ToLower()
}

function Scarica-Lhm($destinazione) {
    # Scarica LibreHardwareMonitorLib e le sue dipendenze da nuget.org,
    # prendendo da ogni pacchetto la versione per .NET Framework.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'   # la barra di avanzamento rallenta molto i download
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $base = 'https://api.nuget.org/v3-flatcontainer'
    $tmp = Join-Path $env:TEMP ('ilomon-nuget-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    New-Item -ItemType Directory -Force -Path $destinazione | Out-Null
    $elenco = @()
    try {
        $versioni = @((Invoke-RestMethod -Uri "$base/librehardwaremonitorlib/index.json" -UseBasicParsing).versions)
        $radice = @($versioni | Where-Object { $_ -notmatch '-' })[-1]
        $coda = New-Object System.Collections.Queue
        $coda.Enqueue(@('LibreHardwareMonitorLib', $radice))
        $fatti = @{}
        while ($coda.Count -gt 0) {
            $voce = $coda.Dequeue()
            $id = "$($voce[0])"; $ver = "$($voce[1])".ToLower(); $chiave = $id.ToLower()
            if ($fatti.ContainsKey($chiave) -or $PacchettiDiSistema -contains $chiave) { continue }
            $fatti[$chiave] = $ver
            $pacchetto = Join-Path $tmp "$chiave.$ver.nupkg"
            Invoke-WebRequest -Uri "$base/$chiave/$ver/$chiave.$ver.nupkg" -OutFile $pacchetto -UseBasicParsing
            $dir = Join-Path $tmp $chiave
            [IO.Compression.ZipFile]::ExtractToDirectory($pacchetto, $dir)

            # Alcuni pacchetti (LibreHardwareMonitorLib compreso) tengono la
            # libreria per architettura, in runtimes\win-x64\lib\<versione>.
            $scelta = $null; $cartellaScelta = $null
            foreach ($t in $TfmUtili) {
                foreach ($c in @("runtimes\$Architettura\lib\$t", "lib\$t")) {
                    if (Test-Path (Join-Path $dir $c)) { $scelta = $t; $cartellaScelta = Join-Path $dir $c; break }
                }
                if ($scelta) { break }
            }
            $nativa = Join-Path $dir "runtimes\$Architettura\native"
            if (Test-Path $nativa) {
                Get-ChildItem -Path $nativa -Filter '*.dll' | ForEach-Object { Copy-Item -Path $_.FullName -Destination $destinazione -Force }
            }
            if ($scelta) {
                $dll = @(Get-ChildItem -Path $cartellaScelta -Filter '*.dll')
                foreach ($f in $dll) { Copy-Item -Path $f.FullName -Destination $destinazione -Force }
                if ($dll.Count) { $elenco += "$id $ver ($scelta)" }
            } elseif ($chiave -eq 'librehardwaremonitorlib') {
                throw "il pacchetto LibreHardwareMonitorLib $ver non ha una versione per .NET Framework"
            }

            $nuspec = Get-ChildItem -Path $dir -Filter '*.nuspec' | Select-Object -First 1
            if (-not $nuspec) { continue }
            [xml]$x = Get-Content -Path $nuspec.FullName -Raw
            $nodo = $x.package.metadata.dependencies
            if (-not $nodo) { continue }
            $dipendenze = @()
            $gruppi = @($nodo.ChildNodes | Where-Object { $_.LocalName -eq 'group' })
            if ($gruppi.Count) {
                $gruppo = $null
                $ordine = @()
                if ($scelta) { $ordine += $scelta }
                $ordine += $TfmUtili
                foreach ($t in $ordine) {
                    $gruppo = $gruppi | Where-Object { (Tfm-Breve $_.GetAttribute('targetFramework')) -eq $t } | Select-Object -First 1
                    if ($gruppo) { break }
                }
                if (-not $gruppo) { $gruppo = $gruppi | Where-Object { -not $_.GetAttribute('targetFramework') } | Select-Object -First 1 }
                if ($gruppo) { $dipendenze = @($gruppo.ChildNodes | Where-Object { $_.LocalName -eq 'dependency' }) }
            } else {
                $dipendenze = @($nodo.ChildNodes | Where-Object { $_.LocalName -eq 'dependency' })
            }
            foreach ($d in $dipendenze) {
                $coda.Enqueue(@($d.GetAttribute('id'), (Versione-Minima $d.GetAttribute('version'))))
            }
        }
    } finally {
        Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem -Path $destinazione -Filter '*.dll' | Unblock-File -ErrorAction SilentlyContinue
    $elenco | Out-File -FilePath (Join-Path $destinazione 'nuget.txt') -Encoding UTF8
    return ,$elenco
}

function Installa-Lhm {
    # Si scarica in una cartella nuova; le precedenti si tolgono se si
    # puo' (se sono in uso restano, e verranno tolte la volta dopo).
    $nuova = Join-Path $Cartella ('lhm-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    try {
        $elenco = Scarica-Lhm $nuova
    } catch {
        Remove-Item -Path $nuova -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    Get-ChildItem -Path $Cartella -Directory -ErrorAction SilentlyContinue |
        Where-Object { ($_.Name -eq 'lhm' -or $_.Name -like 'lhm-*' -or $_.Name -like 'lhm.*') -and $_.FullName -ne $nuova } |
        ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    return ,$elenco
}

function PawnIO-Installato {
    foreach ($radice in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO')) {
        try {
            $v = (Get-ItemProperty -Path $radice -ErrorAction Stop).DisplayVersion
            if ($v) { return "$v" }
        } catch { }
    }
    return $null
}

function Numero($v) {
    if ($null -eq $v) { return $null }
    $x = [double]$v
    if ([double]::IsNaN($x) -or [double]::IsInfinity($x)) { return $null }
    return [math]::Round($x, 1)
}

function Leggi-Sensori {
    if (-not (Lhm-Pronto)) {
        throw "libreria di LibreHardwareMonitor non installata: rilanciare lo script con -Installa"
    }
    $cartellaLib = Cartella-Lhm-Attiva
    if (-not ('IloMonitorLhm2' -as [type])) {
        Add-Type -TypeDefinition $CodiceRisolutore -Language CSharp -ErrorAction Stop
    }
    [IloMonitorLhm2]::Registra($cartellaLib)
    $lib = [Reflection.Assembly]::LoadFrom((Join-Path $cartellaLib 'LibreHardwareMonitorLib.dll'))

    # PowerShell 5 gira su .NET Framework: una libreria compilata per
    # .NET moderno si carica ma non funziona. Si riconosce dai riferimenti.
    $riferimenti = @($lib.GetReferencedAssemblies())
    if (-not ($riferimenti | Where-Object { $_.Name -eq 'mscorlib' })) {
        $rt = $riferimenti | Where-Object { $_.Name -eq 'System.Runtime' } | Select-Object -First 1
        $quale = if ($rt) { ".NET $($rt.Version.Major)" } else { '.NET moderno' }
        throw "la libreria in $cartellaLib e' per ${quale}, non per .NET Framework: rilanciare lo script con -Installa"
    }
    try {
        $tipo = $lib.GetType('LibreHardwareMonitor.Hardware.Computer', $true)
        $pc = [Activator]::CreateInstance($tipo)
    } catch {
        $e = $_.Exception
        $dettagli = @($e.GetBaseException().Message)
        $rtl = $e
        while ($rtl -and -not ($rtl -is [Reflection.ReflectionTypeLoadException])) { $rtl = $rtl.InnerException }
        if ($rtl) { $dettagli += @($rtl.LoaderExceptions | Select-Object -First 3 | ForEach-Object { $_.Message }) }
        throw "libreria di LibreHardwareMonitor non caricabile: $($dettagli -join ' | ')"
    }
    $pc.IsCpuEnabled = $true
    $pc.IsMotherboardEnabled = $true
    $pc.IsMemoryEnabled = $true
    $pc.IsGpuEnabled = $true
    $pc.IsPsuEnabled = $true
    $pc.Open()
    try {
        $tutti = New-Object System.Collections.ArrayList
        $raccogli = {
            param($hw)
            $hw.Update()
            foreach ($sub in $hw.SubHardware) { & $raccogli $sub }
        }
        # Il carico si calcola fra due letture: la prima prepara, la
        # seconda misura.
        foreach ($hw in $pc.Hardware) { & $raccogli $hw }
        Start-Sleep -Milliseconds 1500
        foreach ($hw in $pc.Hardware) { & $raccogli $hw }

        $elenca = {
            param($hw)
            foreach ($s in $hw.Sensors) { [void]$tutti.Add($s) }
            foreach ($sub in $hw.SubHardware) { & $elenca $sub }
        }
        foreach ($hw in $pc.Hardware) { & $elenca $hw }

        $temperature = @()
        $ventole = @()
        $caricoCpu = $null; $memoria = $null; $potenzaCpu = $null
        foreach ($s in $tutti) {
            $v = Numero $s.Value
            if ($null -eq $v) { continue }
            $tipoHw = "$($s.Hardware.HardwareType)"
            $nome = "$($s.Name)".Trim()
            switch ("$($s.SensorType)") {
                'Temperature' {
                    # Un valore per sensore utile: niente singoli core
                    # e niente "distanza dal limite", che non e' una
                    # temperatura.
                    if ($nome -match 'Distance to TjMax|Limit|Threshold|Resolution|^CPU Core #\d+|^Core #\d+|^P-Core #\d+|^E-Core #\d+') { continue }
                    if ($v -le 5 -or $v -ge 125) { continue }
                    $temperature += New-Object PSObject -Property ([ordered]@{
                        gruppo = $tipoHw; componente = "$($s.Hardware.Name)"; nome = $nome; valore = $v })
                }
                'Fan' {
                    if ($v -le 0) { continue }   # connettore senza ventola
                    $ventole += New-Object PSObject -Property ([ordered]@{
                        gruppo = $tipoHw; componente = "$($s.Hardware.Name)"; nome = $nome; giri = [int]$v })
                }
                'Load' {
                    if ($tipoHw -eq 'Cpu' -and $nome -eq 'CPU Total' -and $null -eq $caricoCpu) { $caricoCpu = $v }
                    if ($tipoHw -eq 'Memory' -and $nome -eq 'Memory' -and "$($s.Hardware.Name)" -notmatch 'Virtual' -and $null -eq $memoria) { $memoria = $v }
                }
                'Power' {
                    if ($tipoHw -eq 'Cpu' -and $nome -match '^(CPU )?Package$' -and $null -eq $potenzaCpu) { $potenzaCpu = $v }
                }
            }
        }
        $versione = $null
        try { $versione = "$($lib.GetName().Version)" } catch { }
        return New-Object PSObject -Property ([ordered]@{
            temperature = @($temperature)
            ventole     = @($ventole)
            carico_cpu  = $caricoCpu
            memoria     = $memoria
            potenza_cpu = $potenzaCpu
            fonte       = "LibreHardwareMonitor $versione"
            pawnio      = PawnIO-Installato
        })
    } finally {
        try { $pc.Close() } catch { }
    }
}

# ------------------------------------------------------------------
# Inventario dal sistema operativo (per i server la cui scheda di
# gestione non lo conosce)
# ------------------------------------------------------------------

function Testo-Utile($v) {
    $t = "$v".Trim()
    if (-not $t -or $t -match '^(System Product Name|System manufacturer|System Serial Number|To be filled by O\.E\.M\.|Default string|Not Applicable|None|0+)$') { return $null }
    return $t
}

function Leggi-Inventario {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $scheda = Get-CimInstance Win32_BaseBoard
    $tipiMemoria = @{20='DDR';21='DDR2';24='DDR3';26='DDR4';34='DDR5';35='LPDDR5'}

    # Sulle schede madri da PC il modello del "sistema" e' un segnaposto:
    # quello vero e' il modello della scheda madre.
    $modello = Testo-Utile $cs.Model
    $produttore = Testo-Utile $cs.Manufacturer
    if (-not $modello) { $modello = Testo-Utile $scheda.Product; $produttore = Testo-Utile $scheda.Manufacturer }
    $seriale = Testo-Utile $bios.SerialNumber
    if (-not $seriale) { $seriale = Testo-Utile $scheda.SerialNumber }
    $dataBios = $null
    try { if ($bios.ReleaseDate) { $dataBios = $bios.ReleaseDate.ToString('dd/MM/yyyy') } } catch { }

    $processori = @(Get-CimInstance Win32_Processor | ForEach-Object {
        New-Object PSObject -Property ([ordered]@{
            socket = "$($_.SocketDesignation)".Trim(); modello = "$($_.Name)".Trim()
            produttore = "$($_.Manufacturer)".Trim(); mhz = $_.MaxClockSpeed
            core = $_.NumberOfCores; thread = $_.NumberOfLogicalProcessors })
    })
    $memoria = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        $tipo = $null
        try { $tipo = $tipiMemoria[[int]$_.SMBIOSMemoryType] } catch { }
        $mhz = $_.ConfiguredClockSpeed
        if (-not $mhz) { $mhz = $_.Speed }
        New-Object PSObject -Property ([ordered]@{
            posizione = "$($_.DeviceLocator)".Trim(); mib = [int64]($_.Capacity / 1MB)
            mhz = $mhz; tipo = $tipo; produttore = "$($_.Manufacturer)".Trim()
            codice = "$($_.PartNumber)".Trim() })
    })
    return New-Object PSObject -Property ([ordered]@{
        hostname   = "$($cs.DNSHostName)"
        produttore = $produttore
        modello    = $modello
        seriale    = $seriale
        bios       = (@("$($bios.SMBIOSBIOSVersion)".Trim(), $dataBios) | Where-Object { $_ }) -join ' '
        so         = "$($os.Caption)".Trim() + ' ' + "$($os.Version)"
        avvio      = $os.LastBootUpTime.ToUniversalTime().ToString('s')
        processori = $processori
        memoria    = $memoria
    })
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
    if ($InviaSensori) {
        Write-Host "Scarico la libreria di LibreHardwareMonitor da nuget.org..."
        try {
            $elenco = Installa-Lhm
            Write-Host "Libreria installata in $(Cartella-Lhm-Attiva):"
            $elenco | ForEach-Object { Write-Host "   $_" }
        } catch {
            Write-Host "Download non riuscito: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Lhm-Pronto) { Write-Host "Resta in uso la libreria gia' presente." -ForegroundColor Yellow }
            else { Write-Host "I sensori non verranno inviati finche' -Installa non riesce a scaricarla." -ForegroundColor Yellow }
        }
        if (-not (PawnIO-Installato)) {
            Write-Host "Driver PawnIO non installato: senza, CPU e scheda madre non si leggono." -ForegroundColor Yellow
            Write-Host "Installalo con:  winget install namazso.PawnIO   (poi rilancia -Mostra)" -ForegroundColor Yellow
        }
    }
    $azione = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$destinazione`""
    # Con i sensori ogni 5 minuti (i dischi restano ogni ora), senza ogni ora.
    $intervallo = if ($InviaSensori) { New-TimeSpan -Minutes 5 } else { New-TimeSpan -Hours 1 }
    $ogniOra = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
        -RepetitionInterval $intervallo -RepetitionDuration (New-TimeSpan -Days 3650)
    $avvio = New-ScheduledTaskTrigger -AtStartup
    $utente = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $impostazioni = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $NomeAttivita -Action $azione `
        -Trigger @($ogniOra, $avvio) -Principal $utente -Settings $impostazioni -Force | Out-Null
    if ($InviaSensori) {
        Write-Host "Attivita' pianificata '$NomeAttivita' creata: sensori ogni 5 minuti, dischi ogni ora, e all'avvio."
    } else {
        Write-Host "Attivita' pianificata '$NomeAttivita' creata: invio ogni ora e all'avvio."
    }
    Write-Host "Script installato in $destinazione"
}

# ---------------------------------------------------------------- lettura e invio
# I dischi cambiano lentamente: con l'invio ogni 5 minuti dei sensori
# li si rilegge solo una volta all'ora.
$fareDischi = $true
if ($InviaSensori -and -not $Installa -and -not $Mostra) {
    try {
        $ultimo = (Get-Item $FileDischi -ErrorAction Stop).LastWriteTime
        if (((Get-Date) - $ultimo).TotalMinutes -lt 55) { $fareDischi = $false }
    } catch { }
}

$dischi = $null
if ($fareDischi) {
    try {
        $dischi = Leggi-Dischi
    } catch {
        Scrivi-Log "ERRORE lettura dischi: $($_.Exception.Message)"
        Write-Host "Lettura dei dischi non riuscita: $($_.Exception.Message)" -ForegroundColor Red
        if (-not $InviaSensori) { exit 1 }
    }
}

$sensori = $null
$erroreSensori = $null
$inventario = $null
if ($InviaSensori) {
    try { $sensori = Leggi-Sensori } catch { $erroreSensori = $_.Exception.Message }
    if ($fareDischi) {
        try { $inventario = Leggi-Inventario } catch { }
    }
}

if ($Mostra) {
    if ($null -ne $dischi) {
        $dischi | Select-Object modello, seriale, bus, tipo, salute,
            @{n='usura NVMe %'; e={ if ($_.nvme) { $_.nvme.percentuale_usata } }},
            @{n='ore'; e={ if ($_.nvme) { $_.nvme.ore_accensione } else { $_.ore_accensione } }},
            @{n='anni'; e={ $o = if ($_.nvme) { $_.nvme.ore_accensione } else { $_.ore_accensione }; if ($o) { [math]::Round($o / 8760, 1) } }},
            @{n='attributi SMART'; e={ if ($_.ata) { $_.ata.Count } }} |
            Format-Table -AutoSize
        Write-Host "$($dischi.Count) dischi letti."
    }
    if ($InviaSensori) {
        if ($sensori) {
            $sensori.temperature | Select-Object gruppo, componente, nome, @{n='gradi C'; e={ $_.valore }} | Format-Table -AutoSize
            $sensori.ventole | Select-Object gruppo, componente, nome, giri | Format-Table -AutoSize
            Write-Host ("Carico CPU: {0} %   Memoria: {1} %   Potenza CPU: {2} W" -f $sensori.carico_cpu, $sensori.memoria, $sensori.potenza_cpu)
            Write-Host "$($sensori.fonte); driver PawnIO: $(if ($sensori.pawnio) { $sensori.pawnio } else { 'NON installato' })"
            if ($inventario) {
                Write-Host ("Sistema: {0} {1} - {2} - BIOS {3}" -f $inventario.produttore, $inventario.modello, $inventario.so, $inventario.bios)
                $inventario.processori | ForEach-Object { Write-Host ("CPU: {0} ({1} core, {2} thread)" -f $_.modello, $_.core, $_.thread) }
                Write-Host ("Memoria: {0} moduli, {1} GB" -f @($inventario.memoria).Count, [math]::Round((@($inventario.memoria) | Measure-Object mib -Sum).Sum / 1024))
            }
            if (-not $sensori.pawnio) {
                Write-Host "Senza PawnIO mancano CPU e scheda madre: installalo con  winget install namazso.PawnIO" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Sensori non letti: $erroreSensori" -ForegroundColor Yellow
        }
    }
    Write-Host "(nessun invio: modalita' -Mostra)"
    return
}

$pacchetto = [ordered]@{
    host     = $env:COMPUTERNAME
    versione = 3
}
if ($null -ne $dischi) { $pacchetto.dischi = @($dischi) }
if ($sensori) { $pacchetto.sensori = $sensori }
if ($inventario) { $pacchetto.inventario = $inventario }
if ($erroreSensori) { $pacchetto.errore_sensori = "$erroreSensori" }
$corpo = $pacchetto | ConvertTo-Json -Depth 6

try {
    $risposta = Invoke-RestMethod -Uri "$Pannello/api/agent/drives" -Method Post `
        -Body ([Text.Encoding]::UTF8.GetBytes($corpo)) `
        -ContentType 'application/json; charset=utf-8' `
        -Headers @{ Authorization = "Bearer $Chiave" } -TimeoutSec 60 -UseBasicParsing
    $parti = @()
    if ($null -ne $dischi) {
        $parti += "$($risposta.salvati) dischi"
        try { New-Item -ItemType Directory -Force -Path $Cartella | Out-Null; Get-Date | Out-File -FilePath $FileDischi -Encoding ASCII } catch { }
    }
    if ($sensori) { $parti += "$($risposta.sensori) sensori" }
    if ($erroreSensori) { $parti += "sensori non letti ($erroreSensori)" }
    $messaggio = "OK: $($parti -join ', ') inviati a $Pannello"
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
