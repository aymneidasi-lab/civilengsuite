/**
 * Static file server for encrypted files
 * This runs server-side so it can read from the filesystem
 */

import { readFileSync } from 'fs';
import { join } from 'path';

export default function handler(req, res) {
  const { file } = req.query;

  // Only allow our specific enc files — nothing else
  if (!file || !['pc_suite.enc', 'footing_pro.enc'].includes(file)) {
    res.status(404).send('Not found');
    return;
  }

  try {
    const filePath = join(process.cwd(), 'public', file);
    const content = readFileSync(filePath, 'utf-8');
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(content);
  } catch (err) {
    res.status(500).send(`Cannot read file: ${err.message}`);
  }
}
