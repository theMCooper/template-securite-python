/*
 * Règles personnelles du TP2 (préfixe Triage_ pour éviter tout conflit
 * de nom avec les règles fournies).
 */

rule Triage_Prompt_Injection
{
    meta:
        description = "Texte qui s'adresse à une IA ou tente de blanchir le fichier"
    strings:
        $ai1 = "AI_INSTRUCTIONS" nocase wide ascii
        $ai2 = "NOTE_TO_AI" nocase wide ascii
        $ig1 = "ignore previous instructions" nocase wide ascii
        $ig2 = "ignore all previous" nocase wide ascii
        $ig3 = "ignore les instructions" nocase wide ascii
        $wl1 = "mark the sample clean" nocase wide ascii
        $wl2 = "disregard all" nocase wide ascii
        $wl3 = /th(is|e) (file|sample) is (clean|safe|benign)/ nocase wide ascii
    condition:
        any of them
}

rule Triage_C2_Config_With_Persistence
{
    meta:
        description = "Configuration C2 (mutex ou URL de panneau) + clé Run"
        mitre = "T1547.001, T1071.001"
    strings:
        $run   = "\\CurrentVersion\\Run\\" nocase wide ascii
        $mutex = /(Global|Local)\\[A-Za-z0-9_]{4,}/ wide ascii
        $gate  = /https?:\/\/[a-z0-9.\-]+(:[0-9]{1,5})?\/[a-z0-9_\/\-]*[a-z0-9_]+\.php/ nocase wide ascii
    condition:
        $run and ($mutex or $gate)
}
