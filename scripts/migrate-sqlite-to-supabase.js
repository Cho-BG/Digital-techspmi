import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import initSqlJs from 'sql.js';
import { closeDB, getDB, initDB, transaction } from '../database.js';
import { hashPassword, isPasswordHash } from '../security.js';

const defaultPaths = [path.resolve('data.db'), path.resolve('public/dashboard/data.db')];
const sourceArg = process.argv.slice(2).find(argument => !argument.startsWith('--'));
const sqlitePath = path.resolve(sourceArg || defaultPaths.find(fs.existsSync) || 'data.db');
if (!fs.existsSync(sqlitePath)) throw new Error(`SQLite database not found: ${sqlitePath}`);
if (!process.argv.includes('--replace')) {
  throw new Error('This replaces Supabase table data. Re-run with --replace after verifying DATABASE_URL.');
}

const tables = [
  'users', 'admin_accounts', 'system_settings', 'password_recovery_requests', 'dpk_lessons',
  'grades', 'attendance', 'dpk_programs', 'dpk_program_teachers', 'schedule_entries',
  'booking_requests', 'evaluation_results', 'attendance_records', 'attendance_assignments',
  'attendance_assignment_records', 'dpk_program_groups', 'dpk_program_evaluators',
  'dpk_teacher_lesson_dates'
];

const SQL = await initSqlJs();
const sqlite = new SQL.Database(fs.readFileSync(sqlitePath));
const sourceTables = new Set((sqlite.exec(`SELECT name FROM sqlite_master WHERE type = 'table'`)[0]?.values || []).map(([name]) => name));
if (!sourceTables.has('users') || !sourceTables.has('admin_accounts')) {
  throw new Error(`SQLite source has no application schema: ${sqlitePath}`);
}
await initDB();
const db = getDB();

function sqliteRows(table) {
  if (!sourceTables.has(table)) return [];
  const result = sqlite.exec(`SELECT * FROM "${table}"`)[0];
  if (!result) return [];
  return result.values.map(values => {
    const row = Object.fromEntries(result.columns.map((column, index) => [column, values[index]]));
    if (['users', 'admin_accounts'].includes(table) && !isPasswordHash(row.password)) row.password = hashPassword(row.password);
    return row;
  });
}

const sourceRows = Object.fromEntries(tables.map(table => [table, sqliteRows(table)]));
const ids = table => new Set(sourceRows[table].map(row => Number(row.id)));
const userIds = ids('users');
const lessonIds = ids('dpk_lessons');
const programIds = ids('dpk_programs');
const assignmentIds = new Set(sourceRows.attendance_assignments
  .filter(row => programIds.has(Number(row.program_id)))
  .map(row => Number(row.id)));

function migrationRow(table, sourceRow) {
  const row = { ...sourceRow };
  const nullableReferences = {
    password_recovery_requests: [['user_id', userIds]],
    dpk_lessons: [['teacher_id', userIds]],
    grades: [['student_id', userIds], ['lesson_id', lessonIds]],
    attendance: [['student_id', userIds], ['lesson_id', lessonIds]],
    schedule_entries: [['program_id', programIds], ['teacher_id', userIds]],
    booking_requests: [['reviewed_by', userIds]]
  };
  for (const [column, validIds] of nullableReferences[table] || []) {
    if (row[column] !== null && row[column] !== undefined && !validIds.has(Number(row[column]))) row[column] = null;
  }

  const requiredReferences = {
    dpk_program_teachers: [['program_id', programIds], ['teacher_id', userIds]],
    evaluation_results: [['program_id', programIds], ['student_id', userIds]],
    attendance_records: [['program_id', programIds], ['student_id', userIds]],
    attendance_assignments: [['program_id', programIds]],
    attendance_assignment_records: [['assignment_id', assignmentIds], ['student_id', userIds]],
    dpk_program_groups: [['program_id', programIds]],
    dpk_program_evaluators: [['program_id', programIds], ['teacher_id', userIds]],
    dpk_teacher_lesson_dates: [['program_id', programIds], ['teacher_id', userIds]]
  };
  const isValid = (requiredReferences[table] || []).every(([column, validIds]) => validIds.has(Number(row[column])));
  return isValid ? row : null;
}

const targetColumns = {};
for (const table of tables) {
  targetColumns[table] = new Set((await db.all(
    `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ?`,
    [table]
  )).map(row => row.column_name));
  if (!targetColumns[table].size) throw new Error(`Target table is missing: ${table}. Apply supabase/migrations/001_initial_schema.sql first.`);
}

await transaction(async tx => {
  await tx.run(`TRUNCATE TABLE ${tables.map(table => `"${table}"`).join(', ')} RESTART IDENTITY CASCADE`);
  for (const table of tables) {
    const rows = sourceRows[table];
    let skipped = 0;
    for (const sourceRow of rows) {
      const row = migrationRow(table, sourceRow);
      if (!row) {
        skipped += 1;
        continue;
      }
      const columns = Object.keys(row).filter(column => targetColumns[table].has(column));
      if (!columns.length) continue;
      const names = columns.map(column => `"${column}"`).join(', ');
      await tx.run(`INSERT INTO "${table}" (${names}) VALUES (${columns.map(() => '?').join(', ')})`, columns.map(column => row[column]));
    }
    console.log(`${table}: ${rows.length - skipped} migrated${skipped ? `, ${skipped} orphaned row(s) skipped` : ''}`);
  }

  for (const table of tables) {
    if (!targetColumns[table].has('id')) continue;
    await tx.run(`SELECT setval(pg_get_serial_sequence('${table}', 'id'), COALESCE((SELECT MAX(id) FROM "${table}"), 1), (SELECT COUNT(*) > 0 FROM "${table}"))`);
  }
});

sqlite.close();
await closeDB();
console.log(`Migration complete: ${sqlitePath} -> Supabase PostgreSQL`);
