# Tips to Optimize Scan Results

Here are some best practices to help you get the most accurate and comprehensive results from AuditAgent.

## Code Organization

### 1. Clear File Structure

- Keep related contracts in the same directory
- Use meaningful file and directory names
- Maintain a clean project structure

### 2. Follow standard framework practices

- Use the `/src` repository to store your contracts for Foundry framework
- Use the `/contracts` repository to store your contracts for Hardhat framework
- Use the `/test` repository to store your tests
- Stick to standard import paths

### 3. Code Documentation

- Add detailed NatSpec comments for contracts and functions
- Document complex logic and business rules
- Include inline comments for critical sections

## Contract Best Practices

### 1. Modular Design

- Split large contracts into smaller, focused ones
- Use inheritance and interfaces appropriately
- Keep functions concise and single-purpose

### 2. Standard Compliance

- Follow Solidity style guide
- Use latest stable compiler version
- Implement standard interfaces (ERC20, ERC721, etc.)

## Documentation Context

:::tip Pro Tip
Enterprise users can upload additional documentation to provide context. Make sure to:

- Include architectural diagrams
- Provide business logic documentation
- Add technical specifications
:::

## Common Issues to Address

### 1. Code Quality

- Remove unused variables and functions
- Fix compiler warnings
- Handle all possible error cases

### 2. Security Considerations

- Document trust assumptions
- Mark trusted vs untrusted functions
- Highlight critical security parameters

## Before Scanning

### Checklist

- [ ] Code compiles without warnings
- [ ] All tests are passing
- [ ] Documentation is up to date
- [ ] Removed development/debug code
- [ ] Dependencies are properly specified

:::info Remember
The more organized and well-documented your code is, the more accurate and helpful the audit results will be.
:::
