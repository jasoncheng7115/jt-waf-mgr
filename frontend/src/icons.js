// Every icon the UI uses, by meaning. Views use <Icon name="save" />, never an iconoir name, so one
// meaning always looks the same. Iconoir (MIT): only the icons imported here end up in the bundle.
import {
  Plus, EditPencil, Trash, FloppyDisk, Xmark, Refresh, Download, Upload, Search, Filter, ViewColumns3,
  Check, CheckCircle, XmarkCircle, ArrowLeft, ArrowRight, NavArrowLeft, NavArrowRight, NavArrowDown, NavArrowUp,
  LogOut, LogIn, Copy, Key, Lock, LockSlash, User, Group, Shield, ShieldCheck, ShieldAlert, Play, Flask, SunLight,
  HalfMoon, Computer, Eye, EyeClosed, Link, OpenNewWindow, InfoCircle, WarningTriangle, Settings, ClockRotateRight,
  Undo, Import, Database, Archive, StatsReport, Globe, Prohibition, Laptop, MoreHoriz, Send, Code, Page,
  Fingerprint, Sort, SortUp, SortDown, Erase, Calendar, Book, HelpCircle, Hashtag, Bell, List, GitFork, Server,
  Network, Restart, Timer, Wrench, MultiplePages, FastArrowRight, Reports, Map, Mail, ChatLines, BellNotification, Sparks,
} from '@iconoir/vue'

export const ICONS = {
  add: Plus, edit: EditPencil, delete: Trash, save: FloppyDisk, close: Xmark, cancel: Xmark, dismiss: Xmark,
  refresh: Refresh, reload: Restart, download: Download, upload: Upload, search: Search, filter: Filter,
  columns: ViewColumns3, check: Check, approve: CheckCircle, reject: XmarkCircle, back: ArrowLeft, forward: ArrowRight,
  prev: NavArrowLeft, next: NavArrowRight, expand: NavArrowDown, collapse: NavArrowUp, logout: LogOut, login: LogIn,
  copy: Copy, key: Key, lock: Lock, unlock: LockSlash, user: User, users: Group, shield: Shield,
  verify: ShieldCheck, alert: ShieldAlert, run: Play, test: Flask, light: SunLight, dark: HalfMoon, auto: Computer,
  show: Eye, hide: EyeClosed, link: Link, external: OpenNewWindow, info: InfoCircle, warning: WarningTriangle,
  settings: Settings, history: ClockRotateRight, rollback: Undo, adopt: Import, database: Database, backup: Archive,
  chart: StatsReport, globe: Globe, block: Prohibition, sessions: Laptop, more: MoreHoriz, send: Send, code: Code,
  page: Page, fingerprint: Fingerprint, sort: Sort, sortUp: SortUp, sortDown: SortDown, clear: Erase,
  calendar: Calendar, guide: Book, help: HelpCircle, id: Hashtag, bell: Bell, list: List, change: GitFork,
  server: Server, network: Network, timer: Timer, tool: Wrench, versions: MultiplePages, go: FastArrowRight,
  report: Reports, map: Map, mail: Mail, chat: ChatLines, notify: BellNotification, ai: Sparks,
}
