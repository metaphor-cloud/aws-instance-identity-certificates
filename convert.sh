#!/bin/bash

# Output file
OUTPUT_FILE="certs.js"
rm -f "$OUTPUT_FILE"

# Base directory containing certificates
CERTS_DIR="certs"

# Start building the JSON object
echo "module.exports = {" > "$OUTPUT_FILE"

# Iterate over the first-level directories (dsa, rsa, rsa2048)
for algo_dir in "$CERTS_DIR"/*; do
    if [[ -d "$algo_dir" ]]; then
        algo_name=$(basename "$algo_dir")
        echo "  \"$algo_name\": {" >> "$OUTPUT_FILE"

        # Iterate over files inside each algorithm directory
        first_entry=true
        for cert_file in "$algo_dir"/*.pem; do
            if [[ -f "$cert_file" ]]; then
                region_name=$(basename "$cert_file" .pem)
                cert_contents=$(awk '{printf "%s\\n", $0}' "$cert_file") # Convert newlines to \n

                if [ "$first_entry" = true ]; then
                    first_entry=false
                else
                    echo "," >> "$OUTPUT_FILE"
                fi
                
                echo "    \"$region_name\": \"$cert_contents\"" >> "$OUTPUT_FILE"
            fi
        done

        echo -e "\n  }," >> "$OUTPUT_FILE"
    fi
done

# Close the JSON object
echo "};" >> "$OUTPUT_FILE"

echo "Generated $OUTPUT_FILE successfully!"
