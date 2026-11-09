/**
 * Aegis AI Anomaly Detection Routes
 */

import { aiAnomalyService } from '../services/ai-anomaly.service.js';

export async function aiRoutes(fastify) {
  // 1. Flow Analysis
  fastify.post('/api/ai/analyze-flow', async (request, reply) => {
    const windowData = request.body || {};
    const result = aiAnomalyService.evaluateFlowWindow(windowData);
    return {
      success: true,
      timestamp: new Date().toISOString(),
      analysis: result
    };
  });

  // 2. AI Metrics & Accuracy Report
  fastify.get('/api/ai/metrics', async () => {
    const report = aiAnomalyService.getMetricsReport();
    return {
      success: true,
      service: 'Aegis AI Anomaly Detection Engine',
      model: 'Random Forest (100 Trees) + Isolation Forest Ensemble',
      metrics: report
    };
  });

  // 3. Comparative Benchmark Data (Baseline vs eBPF vs AI)
  fastify.get('/api/ai/benchmark', async () => {
    const benchmark = aiAnomalyService.getBenchmarkReport();
    return {
      success: true,
      benchmark
    };
  });
}
