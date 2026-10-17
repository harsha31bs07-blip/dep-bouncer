import { McpApp, Module, ConfigModule } from '@nitrostack/core';
import { SystemHealthCheck } from './health/system.health.js';

/**
 * Root module of the Dep Bouncer MCP server.
 */
@McpApp({
  module: AppModule,
  server: {
    name: 'dep-bouncer',
    version: '0.1.0'
  },
  logging: {
    level: 'info'
  }
})
@Module({
  name: 'app',
  description: 'Root application module',
  imports: [
    ConfigModule.forRoot()
  ],
  providers: [
    SystemHealthCheck,
  ]
})
export class AppModule {}
