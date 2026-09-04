import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import XLSX from 'xlsx';
import { closeDB, initDB, transaction } from './database.js';

const workbookPath = process.argv[2] || '/Users/cho_bg/Downloads/Практики Кафедра (весна).xlsx';
const importSource = 'room-plans-spring-2026';
const pairTimes = [
  ['08:50', '10:20'], ['10:35', '12:05'], ['12:35', '14:05'], ['14:15', '15:45'],
  ['15:55', '17:20'], ['17:30', '19:00'], ['19:10', '20:40']
];

if (!fs.existsSync(workbookPath)) throw new Error(`Workbook not found: ${workbookPath}`);

await initDB();
const workbook = XLSX.readFile(workbookPath);
const counts = new Map();

await transaction(async db => {
  await db.run(`DELETE FROM schedule_entries WHERE source = ?`, [importSource]);
  for (const sheetName of workbook.SheetNames) {
    const room = sheetName.match(/^\d+/)?.[0];
    if (!room) continue;
    const sheet = workbook.Sheets[sheetName];
    const range = XLSX.utils.decode_range(sheet['!ref']);
    let roomCount = 0;

    for (let row = range.s.r; row <= range.e.r; row += 1) {
      const dates = [];
      for (let column = range.s.c; column <= range.e.c; column += 1) {
        const cell = sheet[XLSX.utils.encode_cell({ r: row, c: column })];
        if (cell?.t !== 'n') continue;
        const parsed = XLSX.SSF.parse_date_code(cell.v);
        if (parsed?.y === 2026) dates.push({ column, parsed });
      }
      if (dates.length < 2) continue;

      for (const { column, parsed } of dates) {
        const date = `${parsed.y}-${String(parsed.m).padStart(2, '0')}-${String(parsed.d).padStart(2, '0')}`;
        const jsDay = new Date(Date.UTC(parsed.y, parsed.m - 1, parsed.d)).getUTCDay();
        const dayOfWeek = jsDay === 0 ? 6 : jsDay - 1;
        for (let pairIndex = 0; pairIndex < pairTimes.length; pairIndex += 1) {
          const [timeStart, timeEnd] = pairTimes[pairIndex];
          const cell = sheet[XLSX.utils.encode_cell({ r: row + 2 + pairIndex, c: column })];
          const title = String(cell?.w ?? cell?.v ?? '').replace(/\r\n?/g, '\n').split('\n')
            .map(line => line.trim()).filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
          if (!title) continue;
          await db.run(`INSERT INTO schedule_entries
            (program_name, teacher_id, group_name, room, day_of_week, time_start, time_end, date, instructor_name, source)
            VALUES (?, NULL, NULL, ?, ?, ?, ?, ?, NULL, ?)`,
          [title, room, dayOfWeek, timeStart, timeEnd, date, importSource]);
          roomCount += 1;
        }
      }
    }
    counts.set(room, roomCount);
  }
});

const total = [...counts.values()].reduce((sum, count) => sum + count, 0);
console.log(`Imported ${total} lessons from ${path.basename(workbookPath)}:`);
for (const [room, count] of counts) console.log(`  ${room}: ${count}`);
await closeDB();
