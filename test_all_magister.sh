#!/bin/bash

# Maak een map aan voor de logs
mkdir -p magister_logs
cd magister_logs

# Functie om een commando uit te voeren en op te slaan
run_test() {
    local cmd="$1"
    local name="$2"
    echo "Running: $cmd"
    echo "=== $name ===" > "${name}.log"
    echo "Command: $cmd" >> "${name}.log"
    echo "Time: $(date)" >> "${name}.log"
    echo "----------------------------------------" >> "${name}.log"
    eval "$cmd" >> "${name}.log" 2>&1
    echo "✅ Completed: ${name}.log"
}

# --- HOOFD FUNCTIES ---
run_test "python3 ../magister.py --all" "01_all"
run_test "python3 ../magister.py --cijfers" "02_cijfers"
run_test "python3 ../magister.py --allejaren" "03_allejaren"
run_test "python3 ../magister.py --rooster" "04_rooster"
run_test "python3 ../magister.py --rooster --van 2025-03-10 --tot 2025-03-17" "05_rooster_maart"
run_test "python3 ../magister.py --absenties" "06_absenties"
run_test "python3 ../magister.py --absenties --van 2025-01-01 --tot 2025-09-26" "07_absenties_lang"
run_test "python3 ../magister.py --studiewijzer" "08_studiewijzer"
run_test "python3 ../magister.py --opdrachten" "09_opdrachten"

# --- COMBINATIES ---
run_test "python3 ../magister.py --rooster --absenties --van 2025-03-10 --tot 2025-03-17" "10_rooster_absenties_maart"
run_test "python3 ../magister.py --cijfers --rooster" "11_cijfers_rooster"

# --- DEBUG & VERBOSE ---
run_test "python3 ../magister.py --rooster --verbose" "12_verbose"
run_test "python3 ../magister.py --rooster --debug 2>&1 | head -50" "13_debug_limited"

# --- --get (raw API call) ---
run_test "python3 ../magister.py --get 'account'" "14_get_account"
run_test "python3 ../magister.py --get 'personen/128101/aanmeldingen'" "15_get_aanmeldingen"

# --- INTERNE OPTIES (alleen als je ze handmatig wilt testen) ---
# Let op: deze vereisen dat je waarden kent (bijv. token, school, etc.)
# run_test "python3 ../magister.py --schoolserver trevianum.magister.net --rooster" "16_schoolserver_override"
# run_test "python3 ../magister.py --config /root/.magisterrc --rooster" "17_config_override"

echo "✅ Alle tests voltooid! Logs staan in de map 'magister_logs'."
