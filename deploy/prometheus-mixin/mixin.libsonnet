// Prometheus Mixin
// Follows the kubernetes-mixin project pattern here: https://github.com/kubernetes-monitoring/kubernetes-mixin
// Mixin design doc: https://docs.google.com/document/d/1A9xvzwqnFVSOZ5fD3blKODXfsat5fg6ZhnKu9LK3lB4/edit

// This file will be imported during build for all Promethei
(import 'config.libsonnet') +
(import 'alerts/alerts.libsonnet') +
(import 'dashboards/dashboards.libsonnet') +
(import 'rules/rules.libsonnet')
