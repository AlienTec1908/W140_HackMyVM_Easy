# W140 - HackMyVM (Easy)
 
![W140.png](W140.png)

## Übersicht

*   **VM:** W140
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=W140)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 4. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/W140_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "W140"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine Upload-Funktion (`upload.php`) gefunden wurde. Diese war anfällig für Remote Code Execution (RCE) über eine Schwachstelle in der Bildverarbeitung (vermutlich CVE-2022-23935, die oft `exiftool` betrifft), was eine Reverse Shell als `www-data` ermöglichte. Als `www-data` wurde eine versteckte Bilddatei `/var/www/.w140.png` gefunden. Die Analyse dieser PNG-Datei mit einem QR-Code-Reader offenbarte das Passwort `BaoeCblP5KGJDmA` für den Benutzer `ghost`. Nach dem Wechsel zu `ghost` wurde die User-Flag gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung einer unsicheren `sudo`-Regel: `ghost` durfte das Skript `/opt/Benz-w140` als `root` ohne Passwort und mit `SETENV` ausführen. Da dieses Skript den `find`-Befehl mit relativem Pfad aufrief, konnte durch PATH-Hijacking (Erstellen einer bösartigen `find`-Datei in `/tmp` und Modifizieren des `PATH`) eine Root-Shell erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `ssh`
*   `ssh-keyscan`
*   `python3` (Exploit-Skript für CVE-2022-23935, `http.server`)
*   `nc` (netcat)
*   `which` (impliziert)
*   `pty` (Python-Modul für Shell-Stabilisierung)
*   `export`
*   `stty`
*   `rm`
*   `mkfifo` (für Reverse Shell)
*   `find`
*   `uname`
*   `ls`
*   `file` (impliziert)
*   `pwd`
*   `cd`
*   `wget`
*   `mv`
*   QR Reader (Online/Offline)
*   `su`
*   `sudo`
*   `cat`
*   `echo`
*   `chmod`
*   `bash`
*   `id`

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "W140" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.116`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Apache 2.4.54 "w140").
    *   `nikto` und `gobuster` auf Port 80 fanden Standardverzeichnisse und die Datei `/upload.php` ("eForenzics Image Forensics").

2.  **Initial Access (RCE via CVE-2022-23935 zu `www-data`):**
    *   Ausnutzung einer RCE-Schwachstelle (vermutlich CVE-2022-23935 im Zusammenhang mit `exiftool` oder einer ähnlichen Bildverarbeitungsbibliothek) über die `/upload.php`.
    *   Ein Python-Exploit-Skript (`CVE-2022-23935.py`) wurde verwendet, um eine Reverse Shell als `www-data` zu erhalten.
    *   Stabilisierung der Shell.

3.  **Privilege Escalation (von `www-data` zu `ghost` via QR-Code-Passwort):**
    *   Als `www-data` wurde mittels `find / -name .w140.png 2>/dev/null` die versteckte Datei `/var/www/.w140.png` gefunden.
    *   Die Datei wurde via Python HTTP-Server auf die Angreifer-Maschine heruntergeladen.
    *   Analyse der PNG-Datei mit einem QR-Code-Reader (z.B. `qreader.online`) offenbarte das Passwort `BaoeCblP5KGJDmA`.
    *   Wechsel zum Benutzer `ghost` mittels `su ghost` und dem Passwort `BaoeCblP5KGJDmA`.
    *   User-Flag `61f1157a5b8f5a4b6729367098fcb2a4` in `/home/ghost/user.txt` gelesen.

4.  **Privilege Escalation (von `ghost` zu `root` via `sudo` und PATH Hijacking):**
    *   `sudo -l` als `ghost` zeigte: `(root) SETENV: NOPASSWD: /opt/Benz-w140`.
    *   Analyse von `/opt/Benz-w140` (ein Bash-Skript) zeigte, dass es Befehle (insbesondere `find`) mit relativen Pfaden aufrief.
    *   PATH-Hijacking:
        1.  `cd /tmp/`
        2.  `echo '/bin/bash' > find`
        3.  `chmod +x find`
        4.  `sudo PATH=/tmp:$PATH /opt/Benz-w140`
    *   Das Skript `/opt/Benz-w140` führte nun das manipulierte `/tmp/find`-Skript (welches `/bin/bash` startete) mit Root-Rechten aus.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `2f9f7d1b4a6ae9d6bbbaf6298c5dcc25` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **RCE via Bild-Upload (CVE-2022-23935):** Ausnutzung einer bekannten Schwachstelle in einer Bildverarbeitungsbibliothek über eine Upload-Funktion.
*   **Passwort in QR-Code:** Ein Passwort wurde in einem QR-Code innerhalb einer versteckten Bilddatei gespeichert.
*   **Unsichere `sudo`-Konfiguration (`SETENV` und relatives Skript):** Die Erlaubnis, ein Skript als `root` mit `SETENV` und `NOPASSWD` auszuführen, das interne Befehle mit relativen Pfaden verwendet, ermöglichte PATH-Hijacking.
*   **PATH Hijacking:** Modifizieren der `PATH`-Umgebungsvariable, um ein bösartiges Skript anstelle eines legitimen Systembefehls auszuführen.

## Flags

*   **User Flag (`/home/ghost/user.txt`):** `61f1157a5b8f5a4b6729367098fcb2a4`
*   **Root Flag (`/root/root.txt`):** `2f9f7d1b4a6ae9d6bbbaf6298c5dcc25`

## Tags

`HackMyVM`, `W140`, `Easy`, `RCE`, `CVE-2022-23935`, `ExifTool`, `QR Code`, `sudo Exploitation`, `PATH Hijacking`, `Privilege Escalation`, `Linux`, `Web`
