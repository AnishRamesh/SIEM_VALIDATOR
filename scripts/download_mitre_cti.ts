import fs from 'fs';
import path from 'path';

const MITRE_CTI_URL = 'https://github.com/mitre/cti/releases/download/ATT%26CK-v19.1/enterprise-attack.json';
const OUTPUT_DIR = path.join(process.cwd(), 'data');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'enterprise-attack.json');

async function main() {
  console.log('Initiating download of MITRE ATT&CK Enterprise CTI v19.1 data...');
  console.log(`URL: ${MITRE_CTI_URL}`);

  try {
    if (!fs.existsSync(OUTPUT_DIR)) {
      fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }

    const response = await fetch(MITRE_CTI_URL);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
    }

    const totalBytes = Number(response.headers.get('content-length') || '0');
    console.log(`Response received. Size: ${(totalBytes / 1024 / 1024).toFixed(2)} MB`);

    const json = await response.json();
    console.log('JSON data successfully parsed in memory.');

    // Write file to disk
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(json, null, 2), 'utf8');
    console.log(`MITRE ATT&CK CTI data successfully written to: ${OUTPUT_FILE}`);

    // Analyze objects for Reconnaissance tactics
    console.log('Analyzing CTI data to extract Reconnaissance (TA0043) techniques...');
    
    // In STIX 2.1, objects are in json.objects
    const objects = json.objects || [];
    console.log(`Total objects loaded from CTI: ${objects.length}`);

    // Find all attack-patterns belonging to Reconnaissance
    const reconTechniques: any[] = [];
    const relationships: any[] = [];

    for (const obj of objects) {
      if (obj.type === 'attack-pattern') {
        const killChainPhases = obj.kill_chain_phases || [];
        const isRecon = killChainPhases.some(
          (phase: any) => phase.kill_chain_name === 'mitre-attack' && phase.phase_name === 'reconnaissance'
        );
        if (isRecon) {
          // Extract External ID (e.g. T1595)
          const externalRef = obj.external_references?.find((ref: any) => ref.source_name === 'mitre-attack');
          const externalId = externalRef ? externalRef.external_id : null;
          reconTechniques.push({
            id: obj.id,
            tid: externalId,
            name: obj.name,
            description: obj.description,
            isSubtechnique: obj.x_mitre_is_subtechnique || false
          });
        }
      } else if (obj.type === 'relationship' && obj.relationship_type === 'subtechnique-of') {
        relationships.push({
          subId: obj.source_ref,
          parentId: obj.target_ref
        });
      }
    }

    console.log(`Found ${reconTechniques.length} attack patterns in Reconnaissance phase.`);

    // Match sub-techniques to parents
    const parentTechniques = reconTechniques.filter(t => !t.isSubtechnique);
    const subTechniques = reconTechniques.filter(t => t.isSubtechnique);

    const mappedHierarchy = parentTechniques.map(p => {
      // Find sub-techniques that have relationship with parent technique
      const subsOfParent = subTechniques.filter(sub => {
        return relationships.some(rel => rel.subId === sub.id && rel.parentId === p.id);
      }).map(sub => ({
        tid: sub.tid,
        name: sub.name
      })).sort((a, b) => a.tid.localeCompare(b.tid));

      return {
        tid: p.tid,
        name: p.name,
        subTechniques: subsOfParent.length > 0 ? subsOfParent : undefined
      };
    }).sort((a, b) => a.tid.localeCompare(b.tid));

    console.log('--- RECONNAISSANCE HIERARCHY ACCORDING TO CTI V19.1 ---');
    console.log(JSON.stringify(mappedHierarchy, null, 2));

    // Save mapping database as a smaller caching file under /data/recon_techniques.json to be highly performant
    const reconFile = path.join(OUTPUT_DIR, 'recon_techniques_v19_1.json');
    fs.writeFileSync(reconFile, JSON.stringify(mappedHierarchy, null, 2), 'utf8');
    console.log(`Extracted Reconnaissance hierarchy saved to: ${reconFile}`);

  } catch (err: any) {
    console.error('Error in download script:', err);
    process.exit(1);
  }
}

main();
