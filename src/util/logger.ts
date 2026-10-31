/**
 * Minimal leveled logger. Colors degrade gracefully when chalk is unavailable
 * or output is not a TTY.
 */
import chalk from 'chalk';

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

const LEVELS: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

export class Logger {
  constructor(private level: LogLevel = 'info') {}

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  private enabled(level: LogLevel): boolean {
    return LEVELS[level] <= LEVELS[this.level];
  }

  error(msg: string): void {
    if (this.enabled('error')) console.error(`${chalk.red('✖')} ${msg}`);
  }

  warn(msg: string): void {
    if (this.enabled('warn')) console.error(`${chalk.yellow('!')} ${msg}`);
  }

  info(msg: string): void {
    if (this.enabled('info')) console.error(`${chalk.cyan('i')} ${msg}`);
  }

  success(msg: string): void {
    if (this.enabled('info')) console.error(`${chalk.green('✔')} ${msg}`);
  }

  debug(msg: string): void {
    if (this.enabled('debug')) console.error(`${chalk.gray('·')} ${chalk.gray(msg)}`);
  }
}

export const logger = new Logger();
