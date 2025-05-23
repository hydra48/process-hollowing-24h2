# Process Hollowing 24H2 (RunPE)

![Windows 11 24H2](https://img.shields.io/badge/Windows-11%2024H2-blue) ![x64](https://img.shields.io/badge/Arch-x64-green)

## Présentation

**Process Hollowing 24H2** est un démonstrateur en **C++** de la technique de _process hollowing_ (alias RunPE) sur **Windows 11 24H2**.  
Il crée un processus « vide » (suspendu), en désolidarise l’image en mémoire, injecte un exécutable tiers via une section NT, puis le relance avec son point d’entrée modifié.

> ⚠️ **Avertissement**  
> Ce code est fourni à titre pédagogique. Je ne suis **pas** responsable de l’utilisation malveillante ou illégale qui en serait faite.

---

## Fonctionnement

1. **Chargement des API NT**  
   Récupère dans `ntdll.dll` les pointeurs vers `NtCreateSection`, `NtMapViewOfSection` et `NtUnmapViewOfSection`.  
2. **Ouverture & mapping local du PE**  
   - `OpenPEFile()`, `MapPEFile()` : ouvre et mappe en mémoire l’exécutable cible pour lecture.  
   - `IsValidPE()` : vérifie les signatures DOS/NT.  
3. **Création du processus hôte**  
   - `CreateProcessA(..., CREATE_SUSPENDED)` : crée un process suspendu (e.g. `notepad.exe`).  
   - `GetProcessAddressInformation64()` : lit le PEB et l’image de base du process hôte.  
4. **Injection via section NT**  
   - `NtCreateSection(… , SEC_IMAGE, PAGE_EXECUTE_READ, ...)` : crée une section à partir du PE injecté.  
   - `NtMapViewOfSection()` : mappe cette section en local et dans le process hôte.  
   - `WriteProcessMemory()` : met à jour dans le PEB l’adresse de l’image injectée.  
   - `SetThreadContext()` : modifie le RIP du thread suspendu vers le point d’entrée du nouveau PE.  
   - `ResumeThread()` : reprend l’exécution du thread, lançant l’injecté.

---

## Prérequis

- **Windows 11** version **24H2** (build 19045.xxxx)  
- **Visual Studio 2022** (C++ Desktop Development)  
- **SDK Windows 10/11**  
- Droits administrateur (pour certains processus protégés)

> Le **patch Windows** qui corrige certaines vulnérabilités de process hollowing (PPL, Protected Process Light) est déployé sur la 24H2 ; cette démonstration fonctionne malgré celui-ci en environnement administrateur.

---

## Compilation

```bash
git clone https://github.com/hydra48/process-hollowing-24h2.git
cd process-hollowing-24h2
