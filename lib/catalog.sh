#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — lib/catalog.sh
# Dynamic TSV parser, query engine, schema validation, and filter utilities.
# =============================================================================

[[ -n "${_TRACEFORGE_LIB_CATALOG_LOADED:-}" ]] && return 0
readonly _TRACEFORGE_LIB_CATALOG_LOADED=1

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/common.sh"

catalog_file() {
    local cat_path
    cat_path="$(project_root)/catalog/tools.tsv"
    if [[ ! -f "$cat_path" ]]; then
        die "Central tool catalog not found at: $cat_path"
    fi
    printf '%s' "$cat_path"
}

# Return total count of catalog records (excluding header)
catalog_count() {
    awk 'NR>1 && NF>=15 {count++} END {print count+0}' "$(catalog_file)"
}

# Fetch single record by numerical ID
catalog_get_by_id() {
    local target_id=$1
    awk -F '\t' -v id="$target_id" 'NR>1 && $1 == id {print; exit}' "$(catalog_file)"
}

# Fetch single record by executable binary name
catalog_get_by_binary() {
    local target_binary=$1
    awk -F '\t' -v bin="$target_binary" 'NR>1 && $3 == bin {print; exit}' "$(catalog_file)"
}

# List all distinct categories in catalog order
catalog_list_categories() {
    awk -F '\t' 'NR>1 && $4!="" && !seen[$4]++ {print $4}' "$(catalog_file)"
}

# List distinct subcategories for a given category
catalog_list_subcategories() {
    local cat_name=$1
    awk -F '\t' -v cat="$cat_name" 'NR>1 && $4==cat && $5!="" && !seen[$5]++ {print $5}' "$(catalog_file)"
}

# Get all tools belonging to a category
catalog_filter_by_category() {
    local cat_name=$1
    awk -F '\t' -v cat="$cat_name" 'NR>1 && $4==cat {print}' "$(catalog_file)"
}

# Get all tools belonging to a category and subcategory
catalog_filter_by_subcategory() {
    local cat_name=$1
    local subcat_name=$2
    awk -F '\t' -v cat="$cat_name" -v sub="$subcat_name" 'NR>1 && $4==cat && $5==sub {print}' "$(catalog_file)"
}

# Search across name, binary, category, subcategory, description, ecosystem, and notes
catalog_search() {
    local query=$1
    local lower_query
    lower_query="$(printf '%s' "$query" | tr '[:upper:]' '[:lower:]')"

    awk -F '\t' -v q="$lower_query" 'NR>1 {
        combined = tolower($2 " " $3 " " $4 " " $5 " " $6 " " $9 " " $14);
        if (index(combined, q)) {
            print $0;
        }
    }' "$(catalog_file)"
}

# Count tools by status (e.g. verified, manual, api, optional)
catalog_count_by_status() {
    local target_status=$1
    awk -F '\t' -v st="$target_status" 'NR>1 && $10 == st {count++} END {print count+0}' "$(catalog_file)"
}

# Count tools by ecosystem (e.g. native, pipx, go, ruby_gem, cargo, manual, api)
catalog_count_by_ecosystem() {
    local target_eco=$1
    awk -F '\t' -v eco="$target_eco" 'NR>1 && $6 == eco {count++} END {print count+0}' "$(catalog_file)"
}

# Validate catalog integrity and schema adherence
catalog_validate() {
    awk -F '\t' '
    BEGIN {
        expected_header = "id\tname\tbinary\tcategory\tsubcategory\tecosystem\tmac_install\tlinux_install\tdescription\tstatus\trequires_root\trequires_api\trequires_hardware\tnotes\tsource_url\ttermux_status\ttermux_package\ttermux_install\ttermux_notes\ttermux_root\ttermux_api\ttermux_hardware";
        errors = 0;
    }
    NR == 1 {
        gsub(/\r/, "");
        if ($0 != expected_header) {
            print "ERROR: Invalid catalog header. Found: " $0 > "/dev/stderr";
            errors++;
        }
        next;
    }
    {
        if (NF < 15 || NF > 22) {
            print "ERROR: Line " NR " has " NF " fields, expected 22." > "/dev/stderr";
            errors++;
        }
        if ($1 !~ /^[0-9]+$/) {
            print "ERROR: Line " NR " has invalid ID: " $1 > "/dev/stderr";
            errors++;
        }
        if (seen_id[$1]++) {
            print "ERROR: Duplicate ID: " $1 " on line " NR > "/dev/stderr";
            errors++;
        }
        if ($3 == "") {
            print "ERROR: Empty binary field on line " NR > "/dev/stderr";
            errors++;
        }
        if (seen_bin[$3]++) {
            print "ERROR: Duplicate binary: " $3 " on line " NR > "/dev/stderr";
            errors++;
        }
        if ($6 !~ /^(native|pipx|go|ruby_gem|cargo|manual|api|source)$/) {
            print "ERROR: Invalid ecosystem: " $6 " on line " NR > "/dev/stderr";
            errors++;
        }
    }
    END {
        if (errors > 0) {
            print "Validation failed with " errors " errors." > "/dev/stderr";
            exit 1;
        }
    }
    ' "$(catalog_file)"
}
