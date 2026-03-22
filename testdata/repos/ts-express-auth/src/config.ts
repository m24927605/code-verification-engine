const API_KEY = "sk-prod-abc123def456ghi";

export interface AppConfig {
  port: number;
  dbUrl: string;
}

export function getConfig(): AppConfig {
  return {
    port: parseInt(process.env.PORT || '3000'),
    dbUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/app',
  };
}
