#!/usr/bin/env python3
"""UI conventions the build enforces (run by tools/build_frontend.sh):

- every button (and every link styled as a button) carries an <Icon>;
- no browser-native <select>: the site's SelectBox only; no native date / time inputs: DatePicker;
- list tables go through DataTable (sort, filter, columns, pages); the few tables that are not lists
  are named in TABLE_EXEMPT with the reason.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'frontend', 'src')

# file name -> why a raw <table> is right there
TABLE_EXEMPT = {
    'DataTable.vue': 'the table component itself',
    'DatePicker.vue': 'the calendar grid of the date picker',
}
SELECT_EXEMPT = {'SelectBox.vue'}
# button classes whose content is the label itself -> why no icon
BUTTON_EXEMPT_CLASSES = {
    'dp-day': 'calendar day cells: the date number is the content',
}


def template(text):
    m = re.search(r'<template>(.*)</template>', text, re.S)
    return m.group(1) if m else ''


def main():
    problems = []
    for dirpath, _, files in os.walk(SRC):
        for name in files:
            if not name.endswith('.vue'):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            tpl = template(open(path, encoding='utf-8').read())
            for m in re.finditer(r'<button\b[^>]*>(.*?)</button>', tpl, re.S):
                cls = re.search(r'\bclass="([^"]*)"', m.group(0).split('>', 1)[0])
                if cls and set(cls.group(1).split()) & set(BUTTON_EXEMPT_CLASSES):
                    continue
                if '<Icon' not in m.group(1):
                    line = tpl[:m.start()].count('\n') + 1
                    problems.append('%s (template line %d): button without <Icon>: %s' % (rel, line, ' '.join(m.group(0).split())[:120]))
            for m in re.finditer(r'<(RouterLink|a)\b([^>]*\bclass="[^"]*\bbtn\b[^"]*"[^>]*)>(.*?)</\1>', tpl, re.S):
                if '<Icon' not in m.group(3):
                    line = tpl[:m.start()].count('\n') + 1
                    problems.append('%s (template line %d): button-style link without <Icon>' % (rel, line))
            # every card title (h2) starts with an icon (user, 2026-11-12)
            for m in re.finditer(r'<h2\b([^>]*)>(.*?)</h2>', tpl, re.S):
                if 'np-head' in m.group(1):        # headings inside the navigation panel, not card titles
                    continue
                if '<Icon' not in m.group(2):
                    line = tpl[:m.start()].count('\n') + 1
                    problems.append('%s (template line %d): card title without <Icon>: %s' % (rel, line, ' '.join(m.group(0).split())[:100]))
            if name not in SELECT_EXEMPT and re.search(r'<select\b', tpl):
                problems.append('%s: native <select>; use SelectBox' % rel)
            if re.search(r'<input\b[^>]*type="(date|datetime-local|time|month|week)"', tpl):
                problems.append('%s: native date / time input; use DatePicker' % rel)
            if name not in TABLE_EXEMPT and re.search(r'<table\b', tpl):
                problems.append('%s: raw <table>; use DataTable (or add it to TABLE_EXEMPT with the reason)' % rel)
    for p in problems:
        print(p)
    print('ui check: %s (%d problems)' % ('OK' if not problems else 'FAILED', len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
