# Open Source Software SCA - Analyseur de vulnérabilités des composants open source de la chaîne d'approvisionnement logicielle

> **Gratuit · Open Source · Outil d'analyse de composition logicielle (SCA) assisté par IA**
>
> 🌐 **Langue** : [简体中文](README.md) · [English](README.en.md) · [Français](README.fr.md) · [日本語](README.ja.md)

Un outil d'analyse de composition logicielle (SCA) entièrement gratuit et open source, qui utilise l'IA pour auditer la sécurité des composants open source de la chaîne d'approvisionnement logicielle. Via son interface graphique Swing, sélectionnez un dossier de code Java / Python / Node.js / Go / Rust / PHP : l'outil détecte automatiquement les configurations de dépendances du projet (pom.xml, build.gradle, package.json, requirements.txt, poetry.lock, go.mod, Cargo.toml, composer.json, jars du dossier lib, etc.), génère une liste Excel des dépendances, interroge un par un chaque composant pour ses vulnérabilités CVE et ses licences, réécrit les résultats dans le classeur Excel et affiche enfin une boîte de dialogue d'achèvement permettant d'ouvrir directement le fichier.

**Prise en charge de quatre langues (i18n)** : l'interface, les journaux et la sortie Excel (noms de feuilles, en-têtes, valeurs d'état) basculent instantanément entre le chinois simplifié, l'English, le Français et le 日本語 ; le choix est conservé automatiquement et restauré au prochain démarrage.

## Fonctionnalités

- **Internationalisation (i18n)** : l'interface, la zone de journaux et la sortie Excel (noms de feuilles / en-têtes / valeurs d'état) prennent en charge quatre langues — chinois simplifié, English, Français, 日本語. Basculez à tout moment via le menu « Langue / Language » ; le choix est sauvegardé automatiquement.
- **Configuration des API de modèles IA** : configurez séparément l'« API IA externe » et l'« API IA interne » (protocole compatible OpenAI), avec baseUrl / apiKey / nom de modèle libres, et un test de connexion en un clic.
- **Analyse de projet par IA** : l'IA lit la structure du dossier et la liste des dépendances, produit un rapport d'analyse du projet et complète les dépendances non couvertes par les règles d'extraction.
- **Trois modes d'analyse des dépendances** :
  1. **Analyser tout le projet** — détection automatique des configurations et extraction « composant (packageId) / version / langage / type d'introduction » :
     - Java : `pom.xml` (avec résolution des variables de version `${property}`), `build.gradle`, jars compilés du dossier `lib` (lecture de pom.properties / pom.xml de META-INF/maven)
     - Node.js : `package.json` (dependencies / devDependencies, etc.)
     - Python : `requirements.txt`, `Pipfile`, `poetry.lock`
     - Go : `go.mod` ; Rust : `Cargo.toml` ; PHP : `composer.json`
  2. **Sélectionner un dossier lib** — analyse directement tous les jars du dossier choisi.
  3. **Lire une archive jar/war** — analyse les jars du dossier lib interne de l'archive (`WEB-INF/lib`, `BOOT-INF/lib`).
- **Liste Excel externe de composants** : importez une liste générée par cet outil ou par un autre (une colonne de nom de composant est requise) ; un sélecteur de composants s'ouvre avec filtre par mot-clé et cases à cocher (tout coché par défaut).
- **Quatre canaux d'interrogation CVE** (au choix ; dégradation automatique en cas d'échec) :
  1. **OSV.dev (recommandé)** : base publique de vulnérabilités maintenue par Google, gratuite sans jeton, agrège GitHub Advisory / NVD et d'autres sources officielles
  2. **OSS Index** : base publique de composants Sonatype (POST /api/v3/component-report)
  3. **mvnrepository** : analyse de la table « Vulnerabilities » de `https://mvnrepository.com/artifact/{groupId}/{artifactId}/{version}`
  4. **Sonatype IQ Server** : API d'entreprise (POST /api/v2/components/details) avec votre jeton PAT
- **Réécriture des vulnérabilités dans Excel** : présence de vulnérabilité, liste des identifiants CVE, sévérité maximale (Critique / Élevée / Moyenne / Faible), score CVSS et plages de versions affectées/corrigées pour chaque CVE, licence du composant (POM Maven Central / npm registry / PyPI / crates.io / Packagist).
- **Suggestions de correctif IA (repli sur l'API officielle)** : l'IA peut générer en option des suggestions de mise à niveau pour les composants vulnérables ; si l'IA est indisponible, les versions officielles retournées par l'API de vulnérabilités sont utilisées automatiquement ; la dernière colonne du classeur enregistre la date d'obtention de la suggestion (date de lecture de l'API) afin de retracer la validité des suggestions si les versions corrigées évoluent ultérieurement.
- **Boîte de dialogue d'achèvement** : après l'analyse, choisissez « Ouvrir Excel / Ouvrir le dossier / Fermer ».

## Sortie Excel

Le classeur Excel généré (`.xlsx`) contient 3 feuilles :

| Feuille | Contenu |
| --- | --- |
| Liste des dépendances | composant (packageId), version, langage, type d'introduction, présence de vulnérabilité, nombre de vulnérabilités, sévérité maximale, identifiants CVE, licence, suggestion de correctif IA, suggestion de l'API officielle, date de la suggestion, méthode d'interrogation, statut (lignes colorées en rouge/vert selon la sévérité) |
| Détail des CVE | identifiant CVE, titre, description, score CVSS, sévérité, plages de versions affectées, lien de référence pour chaque vulnérabilité |
| Analyse IA du projet | conclusions globales de l'IA et suggestions de correctif pour le projet |

## Environnement requis

- JDK 1.8 ou supérieur (le projet est écrit en syntaxe Java 8)
- Maven n'est pas requis pour exécuter (jar pré-packagé) ; Maven 3.6+ est nécessaire uniquement pour recompiler

## Démarrage rapide

### Option 1 : exécution directe (recommandé)

```bat
run.bat
```

Ou manuellement :

```bat
java -jar target\cve-dependency-scanner.jar
```

### Option 2 : recompilation

```bat
mvn package -DskipTests
java -jar target\cve-dependency-scanner.jar
```

## Utilisation

1. **Configuration du modèle IA** (premier onglet) :
   - IA externe : baseUrl compatible OpenAI (ex. `https://api.openai.com/v1`), apiKey, nom du modèle (ex. `gpt-4o-mini`)
   - IA interne : URL du service LLM interne (ex. `http://127.0.0.1:11434/v1` ; avec Ollama, `qwen2.5:14b` directement)
   - Choisissez externe ou interne, cliquez sur « Tester la connexion » puis « Enregistrer la configuration »
2. **Configuration de l'interrogation des vulnérabilités** (deuxième onglet) :
   - Choisissez la méthode (OSV.dev recommandée par défaut ; les autres à la demande)
   - La méthode 4 (IQ Server) requiert l'URL du serveur et le jeton PAT
   - Optionnel : activer « Dégradation automatique » et « Résolution des licences »
3. **Analyse des dépendances** (troisième onglet) :
   - Choisissez le mode d'analyse : ① projet entier / ② dossier lib unique / ③ archive jar/war, puis la cible
   - Optionnel : importer une liste Excel externe, définir le chemin du classeur de sortie
   - Optionnel : cocher « Analyse IA du projet » et « Suggestions de correctif IA »
   - Cliquez dans l'ordre : « ① Analyser les dépendances et générer la liste » → « ② Interroger les vulnérabilités et écrire dans Excel » → « ③ Exécution en un clic » (un clic = analyse + interrogation + rapport)
4. Une fois l'analyse terminée, une **boîte de dialogue d'achèvement** s'affiche — cliquez sur « Ouvrir Excel » pour consulter la liste des vulnérabilités.
5. **Changement de langue** : le menu « Langue / Language » permet de basculer à tout moment entre chinois simplifié / English / Français / 日本語 ; l'interface, les journaux et la sortie Excel changent immédiatement et le choix est conservé.

## Configuration

Toute la configuration est conservée dans `config/app-config.json` (sauvegarde automatique à la fermeture de la fenêtre) :

| Clé | Description |
| --- | --- |
| language | langue de l'interface : zh / en / fr / ja |
| externalAi / internalAi | baseUrl, apiKey, model, délai d'expiration (s) des modèles IA externe/interne |
| queryMethod | méthode d'interrogation : OSV / OSS_INDEX / MVN_REPO / IQ_SERVER |
| iqServerUrl / iqToken | URL et jeton du serveur Sonatype IQ Server |
| fallbackEnabled | dégradation automatique vers d'autres canaux si la méthode principale échoue |
| licenseEnabled | résolution des licences des composants |
| aiAnalyze / aiFix | activer l'analyse IA du projet / les suggestions de correctif IA |

## Structure du projet

```
qcoder/
├── pom.xml                              # configuration de build Maven (jar exécutable)
├── run.bat                              # script de lancement en un clic
├── config/app-config.json               # configuration d'exécution (auto-sauvegardée, inclut la langue)
├── README.md / README.en.md / README.fr.md / README.ja.md   # documentation multilingue
└── src/main/
    ├── java/com/qcoder/cve/
    │   ├── Main.java                    # point d'entrée
    │   ├── ui/MainFrame.java            # fenêtre principale Swing (3 onglets + menu de langue + dialogue d'achèvement)
    │   ├── i18n/I18n.java               # utilitaire i18n (changement de langue / chargement / localisation des statuts)
    │   ├── config/                      # modèle de configuration et persistance
    │   ├── model/                       # modèles de dépendance / vulnérabilité
    │   ├── scan/DependencyScanner.java  # analyseur multilingue de dépendances (3 modes)
    │   ├── cve/                         # 4 canaux de vulnérabilités + résolution de licences + constructeur purl
    │   ├── ai/                          # clients API IA externe/interne et service d'analyse
    │   ├── excel/ExcelReport.java       # liste POI Excel et réécriture des vulnérabilités (multilingue)
    │   └── util/HttpUtil.java           # utilitaires HTTP
    └── resources/i18n/                  # fichiers de ressources chinois / anglais / français / japonais
```

## Technologies

- JDK 1.8 + Swing (interface), Apache POI 5.2.5 (Excel), Gson 2.10.1 (JSON), jsoup 1.17.2 (analyse HTML), Maven + plugin shade (empaquetage)
- Framework i18n maison : ressources UTF-8, bascule à chaud sans redémarrage, repli automatique sur le chinois pour les clés manquantes

## Licence

Ce projet est publié sous la licence [GPL-3.0](LICENSE).
