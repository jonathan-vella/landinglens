resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'authored'
  properties: {
    amount: 10
    category: 'Cost'
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: '2026-11-01T00:00:00Z'
    }
    notifications: {
      authored: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: [
          'authored@example.invalid'
        ]
      }
    }
  }
}
