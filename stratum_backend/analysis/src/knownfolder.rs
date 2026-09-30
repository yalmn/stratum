//! Bekannte Ordner (KNOWNFOLDERID) in Pfaden wie `{1AC14E77-…}\cmd.exe`.
//!
//! Zuordnung von GUID zu Standardpfad laut Microsoft, Dokumentation
//! "KNOWNFOLDERID (Knownfolders.h)", maschinell aus der Tabelle übernommen.
//! Die Umgebungsvariablen darin stammen aus der Registry des untersuchten
//! Systems, nie vom Analyserechner. Nicht aufgelöst werden virtuelle Ordner
//! und Einträge, deren Standardpfad laut Tabelle nur für 32-Bit-Systeme gilt
//! (`ProgramFilesX86`, `ProgramFilesCommonX86`, `SystemX86`) oder von der
//! Sprache abhängt (`LocalizedResourcesDir`).

use stratum_registry::Hive;

/// (GUID klein geschrieben, FOLDERID-Name, Standardpfad oder leer).
const TABLE: &[(&str, &str, &str)] = &[
    (
        "008ca0b1-55b4-4c56-b8a8-4de4b299d3be",
        "AccountPictures",
        "%APPDATA%\\Microsoft\\Windows\\AccountPictures",
    ),
    ("de61d971-5ebc-4f02-a3a9-6c82895e5c04", "AddNewPrograms", ""),
    (
        "724ef170-a42d-4fef-9f26-b60e846fba4f",
        "AdminTools",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    ),
    (
        "b2c5e279-7add-439f-b28c-c41fe1bbf672",
        "AppDataDesktop",
        "%LOCALAPPDATA%\\Desktop",
    ),
    (
        "7be16610-1f7f-44ac-bff0-83e15f2ffca1",
        "AppDataDocuments",
        "%LOCALAPPDATA%\\Documents",
    ),
    (
        "7cfbefbc-de1f-45aa-b843-a542ac536cc9",
        "AppDataFavorites",
        "%LOCALAPPDATA%\\Favorites",
    ),
    (
        "559d40a3-a036-40fa-af61-84cb430a4d34",
        "AppDataProgramData",
        "%LOCALAPPDATA%\\ProgramData",
    ),
    (
        "a3918781-e5f2-4890-b3d9-a7e54332328c",
        "ApplicationShortcuts",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Application Shortcuts",
    ),
    ("1e87508d-89c2-42f0-8a7e-645a0f50ca58", "AppsFolder", ""),
    ("a305ce99-f527-492b-8b1a-7e76fa98d6e4", "AppUpdates", ""),
    (
        "ab5fb87b-7ce2-4f83-915d-550846c9537b",
        "CameraRoll",
        "%USERPROFILE%\\Pictures\\Camera Roll",
    ),
    (
        "9e52ab10-f80d-49df-acb8-4330f5687855",
        "CDBurning",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn",
    ),
    (
        "df7266ac-9274-4867-8d55-3bd661de872d",
        "ChangeRemovePrograms",
        "",
    ),
    (
        "d0384e7d-bac3-4797-8f14-cba229b392b5",
        "CommonAdminTools",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    ),
    (
        "c1bae2d0-10df-4334-bedd-7aa20b227a9d",
        "CommonOEMLinks",
        "%ALLUSERSPROFILE%\\OEM Links",
    ),
    (
        "0139d44e-6afe-49f2-8690-3dafcae6ffb8",
        "CommonPrograms",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
    (
        "a4115719-d62e-491d-aa7c-e74b8be3b067",
        "CommonStartMenu",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
    ),
    (
        "82a5ea35-d9cd-47c5-9629-e15d2f714e6e",
        "CommonStartup",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    ),
    (
        "b94237e7-57ac-4347-9151-b08c6c32d1f7",
        "CommonTemplates",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates",
    ),
    ("0ac0837c-bbf8-452a-850d-79d08e667ca7", "ComputerFolder", ""),
    ("4bfefb45-347d-4006-a5be-ac0cb0567192", "ConflictFolder", ""),
    (
        "6f0cd92b-2e97-45d1-88ff-b0d186b8dedd",
        "ConnectionsFolder",
        "",
    ),
    (
        "56784854-c6cb-462b-8169-88e350acb882",
        "Contacts",
        "%USERPROFILE%\\Contacts",
    ),
    (
        "82a74aeb-aeb4-465c-a014-d097ee346d63",
        "ControlPanelFolder",
        "",
    ),
    (
        "2b0f765d-c0e9-4171-908e-08a611b84ff6",
        "Cookies",
        "%APPDATA%\\Microsoft\\Windows\\Cookies",
    ),
    (
        "b4bfcc3a-db2c-424c-b029-7fe99a87c641",
        "Desktop",
        "%USERPROFILE%\\Desktop",
    ),
    (
        "5ce4a5e9-e4eb-479d-b89f-130c02886155",
        "DeviceMetadataStore",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore",
    ),
    (
        "fdd39ad0-238f-46af-adb4-6c85480369c7",
        "Documents",
        "%USERPROFILE%\\Documents",
    ),
    (
        "7b0db17d-9cd2-4a93-9733-46cc89022e7c",
        "DocumentsLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
    ),
    (
        "374de290-123f-4565-9164-39c4925e467b",
        "Downloads",
        "%USERPROFILE%\\Downloads",
    ),
    (
        "1777f761-68ad-4d8a-87bd-30b759fa33dd",
        "Favorites",
        "%USERPROFILE%\\Favorites",
    ),
    (
        "fd228cb7-ae11-4ae3-864c-16f3910ab8fe",
        "Fonts",
        "%windir%\\Fonts",
    ),
    ("cac52c1a-b53d-4edc-92d7-6b2e8ac19434", "Games", ""),
    (
        "054fae61-4dd8-4787-80b6-090220c4b700",
        "GameTasks",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\GameExplorer",
    ),
    (
        "d9dc8a3b-b784-432e-a781-5a1130a75963",
        "History",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\History",
    ),
    ("52528a6b-b9e3-4add-b60d-588c2dba842d", "HomeGroup", ""),
    (
        "9b74b6a3-0dfd-4f11-9e78-5f7800f2e772",
        "HomeGroupCurrentUser",
        "",
    ),
    (
        "bcb5256f-79f6-4cee-b725-dc34e402fd46",
        "ImplicitAppShortcuts",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts",
    ),
    (
        "352481e8-33be-4251-ba85-6007caedcf9d",
        "InternetCache",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
    ),
    ("4d9f7874-4e0c-4904-967b-40b0d20c3e4b", "InternetFolder", ""),
    (
        "1b3ea5dc-b587-4786-b4ef-bd1dc332aeae",
        "Libraries",
        "%APPDATA%\\Microsoft\\Windows\\Libraries",
    ),
    (
        "bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968",
        "Links",
        "%USERPROFILE%\\Links",
    ),
    (
        "f1b32785-6fba-4fcf-9d55-7b8e7f157091",
        "LocalAppData",
        "%LOCALAPPDATA%",
    ),
    (
        "a520a1a4-1780-4ff6-bd18-167343c5af16",
        "LocalAppDataLow",
        "%USERPROFILE%\\AppData\\LocalLow",
    ),
    (
        "2a00375e-224c-49de-b8d1-440df7ef3ddc",
        "LocalizedResourcesDir",
        "",
    ),
    (
        "4bd8d571-6d19-48d3-be97-422220080e43",
        "Music",
        "%USERPROFILE%\\Music",
    ),
    (
        "2112ab0a-c86a-4ffe-a368-0de96e47012e",
        "MusicLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
    ),
    (
        "c5abbf53-e17f-4121-8900-86626fc2c973",
        "NetHood",
        "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
    ),
    ("d20beec4-5ca8-4905-ae3b-bf251ea09b53", "NetworkFolder", ""),
    (
        "31c0dd25-9439-4f12-bf41-7ff4eda38722",
        "Objects3D",
        "%USERPROFILE%\\3D Objects",
    ),
    (
        "2c36c0aa-5812-4b87-bfd0-4cd0dfb19b39",
        "OriginalImages",
        "%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images",
    ),
    (
        "69d2cf90-fc33-4fb7-9a0c-ebb0f0fcb43c",
        "PhotoAlbums",
        "%USERPROFILE%\\Pictures\\Slide Shows",
    ),
    (
        "a990ae9f-a03b-4e80-94bc-9912d7504104",
        "PicturesLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
    ),
    (
        "33e28130-4e1e-4676-835a-98395c3bc3bb",
        "Pictures",
        "%USERPROFILE%\\Pictures",
    ),
    (
        "de92c1c7-837f-4f69-a3bb-86e631204a23",
        "Playlists",
        "%USERPROFILE%\\Music\\Playlists",
    ),
    ("76fc4e2d-d6ad-4519-a663-37bd56068185", "PrintersFolder", ""),
    (
        "9274bd8d-cfd1-41c3-b35e-b13f55a758f4",
        "PrintHood",
        "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
    ),
    (
        "5e6c858f-0e22-4760-9afe-ea3317b67173",
        "Profile",
        "%USERPROFILE%",
    ),
    (
        "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97",
        "ProgramData",
        "%ALLUSERSPROFILE%",
    ),
    (
        "905e63b6-c1bf-494e-b29c-65b732d3d21a",
        "ProgramFiles",
        "%ProgramFiles%",
    ),
    (
        "6d809377-6af0-444b-8957-a3773f02200e",
        "ProgramFilesX64",
        "%ProgramFiles%",
    ),
    (
        "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e",
        "ProgramFilesX86",
        "",
    ),
    (
        "f7f1ed05-9f6d-47a2-aaae-29d317c6f066",
        "ProgramFilesCommon",
        "%ProgramFiles%\\Common Files",
    ),
    (
        "6365d5a7-0f0d-45e5-87f6-0da56b6a4f7d",
        "ProgramFilesCommonX64",
        "%ProgramFiles%\\Common Files",
    ),
    (
        "de974d24-d9c6-4d3e-bf91-f4455120b917",
        "ProgramFilesCommonX86",
        "",
    ),
    (
        "a77f5d77-2e2b-44c3-a6a2-aba601054a51",
        "Programs",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
    ("dfdf76a2-c82a-4d63-906a-5644ac457385", "Public", "%PUBLIC%"),
    (
        "c4aa340d-f20f-4863-afef-f87ef2e6ba25",
        "PublicDesktop",
        "%PUBLIC%\\Desktop",
    ),
    (
        "ed4824af-dce4-45a8-81e2-fc7965083634",
        "PublicDocuments",
        "%PUBLIC%\\Documents",
    ),
    (
        "3d644c9b-1fb8-4f30-9b45-f670235f79c0",
        "PublicDownloads",
        "%PUBLIC%\\Downloads",
    ),
    (
        "debf2536-e1a8-4c59-b6a2-414586476aea",
        "PublicGameTasks",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer",
    ),
    (
        "48daf80b-e6cf-4f4e-b800-0e69d84ee384",
        "PublicLibraries",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries",
    ),
    (
        "3214fab5-9757-4298-bb61-92a9deaa44ff",
        "PublicMusic",
        "%PUBLIC%\\Music",
    ),
    (
        "b6ebfb86-6907-413c-9af7-4fc2abf07cc5",
        "PublicPictures",
        "%PUBLIC%\\Pictures",
    ),
    (
        "e555ab60-153b-4d17-9f04-a5fe99fc15ec",
        "PublicRingtones",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones",
    ),
    (
        "0482af6c-08f1-4c34-8c90-e17ec98b1e17",
        "PublicUserTiles",
        "%PUBLIC%\\AccountPictures",
    ),
    (
        "2400183a-6185-49fb-a2d8-4a392a602ba3",
        "PublicVideos",
        "%PUBLIC%\\Videos",
    ),
    (
        "52a4f021-7b75-48a9-9f6b-4b87a210bc8f",
        "QuickLaunch",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
    ),
    (
        "ae50c081-ebd2-438a-8655-8a092e34987a",
        "Recent",
        "%APPDATA%\\Microsoft\\Windows\\Recent",
    ),
    (
        "1a6fdba2-f42d-4358-a798-b74d745926c5",
        "RecordedTVLibrary",
        "%PUBLIC%\\RecordedTV.library-ms",
    ),
    (
        "b7534046-3ecb-4c18-be4e-64cd4cb7d6ac",
        "RecycleBinFolder",
        "",
    ),
    (
        "8ad10c31-2adb-4296-a8f7-e4701232c972",
        "ResourceDir",
        "%windir%\\Resources",
    ),
    (
        "c870044b-f49e-4126-a9c3-b52a1ff411e8",
        "Ringtones",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Ringtones",
    ),
    (
        "3eb685db-65f9-4cf6-a03a-e3ef65729f3d",
        "RoamingAppData",
        "%APPDATA%",
    ),
    (
        "aaa8d5a5-f1d6-4259-baa8-78e7ef60835e",
        "RoamedTileImages",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamedTileImages",
    ),
    (
        "00bcfc5a-ed94-4e48-96a1-3f6217f21990",
        "RoamingTiles",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamingTiles",
    ),
    (
        "b250c668-f57d-4ee1-a63c-290ee7d1aa1f",
        "SampleMusic",
        "%PUBLIC%\\Music\\Sample Music",
    ),
    (
        "c4900540-2379-4c75-844b-64e6faf8716b",
        "SamplePictures",
        "%PUBLIC%\\Pictures\\Sample Pictures",
    ),
    (
        "15ca69b3-30ee-49c1-ace1-6b5ec372afb5",
        "SamplePlaylists",
        "%PUBLIC%\\Music\\Sample Playlists",
    ),
    (
        "859ead94-2e85-48ad-a71a-0969cb56a6cd",
        "SampleVideos",
        "%PUBLIC%\\Videos\\Sample Videos",
    ),
    (
        "4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4",
        "SavedGames",
        "%USERPROFILE%\\Saved Games",
    ),
    (
        "3b193882-d3ad-4eab-965a-69829d1fb59f",
        "SavedPictures",
        "%USERPROFILE%\\Pictures\\Saved Pictures",
    ),
    (
        "e25b5812-be88-4bd9-94b0-29233477b6c3",
        "SavedPicturesLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\SavedPictures.library-ms",
    ),
    (
        "7d1d3a04-debb-4115-95cf-2f29da2920da",
        "SavedSearches",
        "%USERPROFILE%\\Searches",
    ),
    (
        "b7bede81-df94-4682-a7d8-57a52620b86f",
        "Screenshots",
        "%USERPROFILE%\\Pictures\\Screenshots",
    ),
    ("ee32e446-31ca-4aba-814f-a5ebd2fd6d5e", "SEARCH_CSC", ""),
    (
        "0d4c3db6-03a3-462f-a0e6-08924c41b5d4",
        "SearchHistory",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\History",
    ),
    ("190337d1-b8ca-4121-a639-6d472d16972a", "SearchHome", ""),
    ("98ec0e18-2098-4d44-8644-66979315a281", "SEARCH_MAPI", ""),
    (
        "7e636bfe-dfa9-4d5e-b456-d7b39851d8a9",
        "SearchTemplates",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\Templates",
    ),
    (
        "8983036c-27c0-404b-8f08-102d10dcfd74",
        "SendTo",
        "%APPDATA%\\Microsoft\\Windows\\SendTo",
    ),
    (
        "7b396e54-9ec5-4300-be0a-2482ebae1a26",
        "SidebarDefaultParts",
        "%ProgramFiles%\\Windows Sidebar\\Gadgets",
    ),
    (
        "a75d362e-50fc-4fb7-ac2c-a8beaa314493",
        "SidebarParts",
        "%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets",
    ),
    (
        "a52bba46-e9e1-435f-b3d9-28daa648c0f6",
        "SkyDrive",
        "%USERPROFILE%\\OneDrive",
    ),
    (
        "767e6811-49cb-4273-87c2-20f355e1085b",
        "SkyDriveCameraRoll",
        "%USERPROFILE%\\OneDrive\\Pictures\\Camera Roll",
    ),
    (
        "24d89e24-2f19-4534-9dde-6a6671fbb8fe",
        "SkyDriveDocuments",
        "%USERPROFILE%\\OneDrive\\Documents",
    ),
    (
        "339719b5-8c47-4894-94c2-d8f77add44a6",
        "SkyDrivePictures",
        "%USERPROFILE%\\OneDrive\\Pictures",
    ),
    (
        "625b53c3-ab48-4ec1-ba1f-a1ef4146fc19",
        "StartMenu",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu",
    ),
    (
        "b97d20bb-f46a-4c97-ba10-5e3608430854",
        "Startup",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    ),
    (
        "43668bf8-c14e-49b2-97c9-747784d784b7",
        "SyncManagerFolder",
        "",
    ),
    (
        "289a9a43-be44-4057-a41b-587a76d7e7f9",
        "SyncResultsFolder",
        "",
    ),
    (
        "0f214138-b1d3-4a90-bba9-27cbc0c5389a",
        "SyncSetupFolder",
        "",
    ),
    (
        "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7",
        "System",
        "%windir%\\system32",
    ),
    ("d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27", "SystemX86", ""),
    (
        "a63293e8-664e-48db-a079-df759e0509f7",
        "Templates",
        "%APPDATA%\\Microsoft\\Windows\\Templates",
    ),
    (
        "9e3995ab-1f9c-4f13-b827-48b24b6c7174",
        "UserPinned",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    ),
    (
        "0762d272-c50a-4bb0-a382-697dcd729b80",
        "UserProfiles",
        "%SystemDrive%\\Users",
    ),
    (
        "5cd7aee2-2219-4a67-b85d-6c9ce15660cb",
        "UserProgramFiles",
        "%LOCALAPPDATA%\\Programs",
    ),
    (
        "bcbd3057-ca5c-4622-b42d-bc56db0ae516",
        "UserProgramFilesCommon",
        "%LOCALAPPDATA%\\Programs\\Common",
    ),
    ("f3ce0f7c-4901-4acc-8648-d5d44b04ef8f", "UsersFiles", ""),
    ("a302545d-deff-464b-abe8-61c8648d939b", "UsersLibraries", ""),
    (
        "18989b1d-99b5-455b-841c-ab7c74e4ddfc",
        "Videos",
        "%USERPROFILE%\\Videos",
    ),
    (
        "491e922f-5643-4af4-a7eb-4e7a138d8174",
        "VideosLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
    ),
    (
        "f38bf404-1d43-42f2-9305-67de0b28fc23",
        "Windows",
        "%windir%",
    ),
];

/// FOLDERID-Name und Standardpfad (falls auflösbar) zu einer GUID.
pub(crate) fn lookup(guid: &str) -> Option<(&'static str, Option<&'static str>)> {
    let guid = guid
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase();
    TABLE
        .iter()
        .find(|(g, _, _)| *g == guid)
        .map(|(_, name, pfad)| (*name, (!pfad.is_empty()).then_some(*pfad)))
}

/// Umgebungsvariablen des untersuchten Systems, gelesen aus der Registry.
#[derive(Debug, Clone, Default)]
pub(crate) struct Umgebung {
    vars: Vec<(String, String)>,
}

fn string_value(hive: &Hive, key: &str, value: &str) -> Option<String> {
    hive.open_key(key)
        .ok()??
        .value(value)
        .ok()??
        .as_string()
        .filter(|s| !s.is_empty())
}

impl Umgebung {
    /// Systemweite Variablen aus der SOFTWARE-Hive: `windir`, `SystemDrive`,
    /// `ProgramFiles`, `ALLUSERSPROFILE`, `PUBLIC`.
    pub(crate) fn system(software: Option<&Hive>) -> Self {
        let mut env = Self::default();
        let Some(sw) = software else {
            return env;
        };
        if let Some(root) = string_value(sw, "Microsoft\\Windows NT\\CurrentVersion", "SystemRoot")
        {
            if let Some(drive) = root.get(..2).filter(|d| d.ends_with(':')) {
                env.set("SystemDrive", drive.to_string());
            }
            env.set("windir", root);
        }
        if let Some(pf) = string_value(sw, "Microsoft\\Windows\\CurrentVersion", "ProgramFilesDir")
        {
            env.set_expanded("ProgramFiles", &pf);
        }
        let profiles = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        if let Some(pd) = string_value(sw, profiles, "ProgramData") {
            env.set_expanded("ALLUSERSPROFILE", &pd);
        }
        if let Some(public) = string_value(sw, profiles, "Public") {
            env.set_expanded("PUBLIC", &public);
        }
        env
    }

    /// Ergänzt die Variablen eines Benutzers: `USERPROFILE` aus der
    /// ProfileList (Profilpfad endet auf den Benutzernamen), `APPDATA` und
    /// `LOCALAPPDATA` aus seinen `User Shell Folders`.
    pub(crate) fn mit_benutzer(&self, software: Option<&Hive>, ntuser: &Hive, user: &str) -> Self {
        let mut env = self.clone();
        let profil = software.and_then(|sw| {
            let list = sw
                .open_key("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
                .ok()??;
            list.subkeys().ok()?.iter().find_map(|sid| {
                let pfad = sid.value("ProfileImagePath").ok()??.as_string()?;
                let letzter = pfad.rsplit('\\').next()?;
                letzter.eq_ignore_ascii_case(user).then_some(pfad)
            })
        });
        if let Some(p) = profil {
            env.set_expanded("USERPROFILE", &p);
        }
        let usf = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
        for (var, wert) in [("APPDATA", "AppData"), ("LOCALAPPDATA", "Local AppData")] {
            if let Some(v) = string_value(ntuser, usf, wert) {
                env.set_expanded(var, &v);
            }
        }
        env
    }

    fn set(&mut self, name: &str, value: String) {
        self.vars.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.vars.push((name.to_string(), value));
    }

    fn set_expanded(&mut self, name: &str, value: &str) {
        if let Some(v) = self.expand(value) {
            self.set(name, v);
        }
    }

    /// Ersetzt `%NAME%` (ohne Beachtung der Groß-/Kleinschreibung). `None`,
    /// wenn eine Variable unbekannt ist; geraten wird nichts.
    pub(crate) fn expand(&self, template: &str) -> Option<String> {
        let mut out = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let end = after.find('%')?;
            let name = &after[..end];
            let (_, wert) = self
                .vars
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))?;
            out.push_str(wert);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
}

/// Löst einen Pfad der Form `{GUID}\Rest` auf: FOLDERID-Name und, wenn
/// möglich, der vollständige Pfad auf dem untersuchten System.
pub(crate) fn resolve(path: &str, env: &Umgebung) -> Option<(&'static str, Option<String>)> {
    let rest = path.strip_prefix('{')?;
    let (guid, tail) = rest.split_once('}')?;
    let (name, template) = lookup(guid)?;
    let voll = template.and_then(|t| env.expand(t)).map(|basis| {
        if tail.is_empty() {
            basis
        } else {
            format!("{basis}{tail}")
        }
    });
    Some((name, voll))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Umgebung {
        let mut e = Umgebung::default();
        e.set("windir", "C:\\Windows".into());
        e.set("SystemDrive", "C:".into());
        e.set_expanded("USERPROFILE", "%SystemDrive%\\Users\\alice");
        e.set_expanded("APPDATA", "%USERPROFILE%\\AppData\\Roaming");
        e
    }

    #[test]
    fn system32_und_benutzerordner() {
        let e = env();
        assert_eq!(
            resolve("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", &e),
            Some(("System", Some("C:\\Windows\\system32\\cmd.exe".into())))
        );
        assert_eq!(
            resolve("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\\Tools\\x.lnk", &e),
            Some((
                "Programs",
                Some("C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Tools\\x.lnk".into())
            ))
        );
    }

    #[test]
    fn nicht_eindeutige_und_unbekannte_variablen_bleiben_offen() {
        let e = env();
        // 32-Bit-Standardpfad laut Tabelle: nur der Name, kein Pfad.
        assert_eq!(
            resolve("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\x.exe", &e),
            Some(("ProgramFilesX86", None))
        );
        // %ProgramFiles% ist hier unbekannt.
        assert_eq!(
            resolve("{6D809377-6AF0-444B-8957-A3773F02200E}\\x.exe", &e),
            Some(("ProgramFilesX64", None))
        );
        assert_eq!(
            resolve("{00000000-0000-0000-0000-000000000000}\\x", &e),
            None
        );
        assert_eq!(resolve("Microsoft.Windows.Explorer", &e), None);
        assert_eq!(e.expand("%UNBEKANNT%\\x"), None);
        assert_eq!(e.expand("%windir"), None);
    }
}
