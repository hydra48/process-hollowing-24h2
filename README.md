# Process Hollowing 24H2 (RunPE)

&#x20;

## Présentation

**Process Hollowing 24H2** est un démonstrateur en **C++** de la technique de *process hollowing* (alias RunPE) sur **Windows 11 24H2**.
Il crée un processus « vide » (suspendu), en désolidarise l’image en mémoire, injecte un exécutable tiers via une section NT, puis le relance avec son point d’entrée modifié.

> ⚠️ **Avertissement**
> Ce code est fourni à titre pédagogique. Je ne suis **pas** responsable de l’utilisation malveillante ou illégale qui en serait faite.

---

## Fonctionnement

1. **Chargement des API NT**
   Récupère dans `ntdll.dll` les pointeurs vers `NtCreateSection`, `NtMapViewOfSection` et `NtUnmapViewOfSection`.
2. **Ouverture & mapping local du PE**

   * `OpenPEFile()`, `MapPEFile()` : ouvre et mappe en mémoire l’exécutable cible pour lecture.
   * `IsValidPE()` : vérifie les signatures DOS/NT.
3. **Création du processus hôte**

   * `CreateProcessA(..., CREATE_SUSPENDED)` : crée un process suspendu (ex. `notepad.exe`).
   * `GetProcessAddressInformation64()` : lit le PEB et l’image de base du process hôte.
4. **Injection via section NT**

   * `NtCreateSection(…, SEC_IMAGE, PAGE_EXECUTE_READ, ...)` : crée une section à partir du PE injecté.
   * `NtMapViewOfSection()` : mappe cette section en local et dans le process hôte.
   * `WriteProcessMemory()` : met à jour dans le PEB l’adresse de l’image injectée.
   * `SetThreadContext()` : modifie le RIP du thread suspendu vers le point d’entrée du nouveau PE.
   * `ResumeThread()` : reprend l’exécution du thread, lançant l’injecté.

---

## Prérequis

* **Windows 11** version **24H2** (build 19045.xxxx)
* **Visual Studio 2022** (C++ Desktop Development)
* **SDK Windows 10/11**
* Droits administrateur (pour certains processus protégés)

> Le **patch Windows** qui corrige certaines vulnérabilités de process hollowing (PPL, Protected Process Light) est déployé sur la 24H2 ; cette démonstration fonctionne malgré celui-ci en environnement administrateur.

---

## Compilation

```bash
git clone https://github.com/hydra48/process-hollowing-24h2.git
cd process-hollowing-24h2
```

1. Ouvrir `process hollowing 24h2.sln` dans Visual Studio.
2. Choisir **Release** / **x64**.
3. **Build** (Ctrl+Maj+B).
4. L’exécutable `process_hollowing_24h2.exe` se trouve dans `process hollowing 24h2\bin\Release\`.

---

## Utilisation

```console
process_hollowing_24h2.exe <Payload.exe> <HostProcess.exe> [options]
```

* `<Payload.exe>` : chemin vers le PE à injecter.
* `<HostProcess.exe>` : chemin vers l’exécutable hôte (ex. `C:\Windows\System32\notepad.exe`).
* **Options**

  * `-v` / `--verbose` : active les logs `[DEBUG]`.
  * `-h` / `--help` : affiche l’aide.

**Exemple** :

```console
process_hollowing_24h2.exe C:\Tools\mytrojan.exe C:\Windows\System32\notepad.exe --verbose
```

---

## FAQ

| Question                                    | Réponse                                                                 |
| ------------------------------------------- | ----------------------------------------------------------------------- |
| **Pourquoi l’injection échoue ?**           | Exécute en tant qu’administrateur et vérifie les chemins.               |
| **Mon antivirus détecte l’opération !**     | Crée une exception antivirus ou lance en sandbox.                       |
| **Peut-on cibler les Processus protégés ?** | Non – Windows 11 PPL bloque certains process système.                   |
| **Le patch Windows 24H2 bloque tout ?**     | Non, en mode administrateur cette démo contourne le patch standard PPL. |

---

## Contact

Pour toute question ou suggestion, retrouvons-nous sur **Discord** :
**hydra2852**

---

## Licence & Responsabilités

Ce projet est distribué sous **Licence MIT** (cf. `LICENSE`).
**Je décline toute responsabilité** en cas d’usage malveillant.
N’utilisez ce code que pour des études, audits ou environnements contrôlés.

---

## Contribuer

1. Fork & clone
2. Branche `feature/…`
3. Commit & push
4. Ouvrez une Pull Request

---

*ℹ️ Hydra48 – 2024*
