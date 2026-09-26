import os
import sys
import json
import hashlib
import argparse
from pathlib import Path


def load_signatures(db_path):
    if not os.path.isfile(db_path):
        return {}
    with open(db_path, 'r') as f:
        return json.load(f)


def get_file_hash(filepath, algo='sha256', chunksize=8192):
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunksize):
            h.update(chunk)
    return h.hexdigest()


def scan_file(filepath, signatures):
    results = []
    fpath = Path(filepath)
    try:
        file_hash = get_file_hash(filepath)
    except (PermissionError, OSError):
        return [{'file': str(fpath), 'status': 'error', 'detail': 'access denied'}]

    threats = []
    for sig_name, sig_hash in signatures.items():
        if file_hash == sig_hash:
            threats.append(sig_name)

    if threats:
        results.append({'file': str(fpath), 'status': 'infected', 'signatures': threats})
    else:
        results.append({'file': str(fpath), 'status': 'clean'})
    return results


def scan_directory(root_dir, signatures):
    results = []
    root = Path(root_dir).resolve()
    for entry in root.rglob('*'):
        if entry.is_file():
            results.extend(scan_file(str(entry), signatures))
    return results


def print_report(results):
    infected = [r for r in results if r['status'] == 'infected']
    errors = [r for r in results if r['status'] == 'error']
    clean = [r for r in results if r['status'] == 'clean']

    print(f"{'='*60}")
    print(f"Сканирование завершено")
    print(f"{'='*60}")
    print(f"Всего проверено:    {len(results)}")
    print(f"Чистых:              {len(clean)}")
    print(f"Заражено:            {len(infected)}")
    print(f"Ошибок доступа:      {len(errors)}")
    print(f"{'='*60}")

    if infected:
        print("\n[!] ОБНАРУЖЕНЫ УГРОЗЫ:")
        print(f"{'='*60}")
        for r in infected:
            sigs = ', '.join(r['signatures'])
            print(f"  Файл: {r['file']}")
            print(f"  Сигнатуры: {sigs}")
            print(f"{'-'*60}")

    if errors:
        print("\n[!] Ошибки доступа к файлам:")
        for r in errors:
            print(f"  {r['file']}")


def main():
    parser = argparse.ArgumentParser(
        description='TDEvuris — простой сигнатурный антивирусный сканер'
    )
    parser.add_argument('path', nargs='?', default='.',
                        help='Путь к файлу или директории для сканирования')
    parser.add_argument('--db',
                        default=os.path.join(os.path.dirname(__file__), 'signatures.json'),
                        help='Путь к файлу базы сигнатур')
    parser.add_argument('--json', action='store_true',
                        help='Вывод результатов в JSON')
    args = parser.parse_args()

    sigs = load_signatures(args.db)
    if not sigs:
        print(f"[!] База сигнатур пуста или не найдена: {args.db}")
        print(f"[*] Добавьте сигнатуры в формате JSON:"
              f' {{"имя_угрозы": "sha256_хеш", ...}}')
    else:
        print(f"[*] Загружено сигнатур: {len(sigs)}")

    target = Path(args.path)
    if not target.exists():
        print(f"[!] Путь не существует: {args.path}")
        sys.exit(1)

    print(f"[*] Сканирование: {target.resolve()}")
    print()

    if target.is_file():
        results = scan_file(str(target), sigs)
    else:
        results = scan_directory(str(target), sigs)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_report(results)

    infected = [r for r in results if r['status'] == 'infected']
    sys.exit(len(infected))


if __name__ == '__main__':
    main()
