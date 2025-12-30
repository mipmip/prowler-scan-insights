## Contributing

## Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


### Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


### Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing.
3. Ensure local tests pass.
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.


## Development Setup

**Important**: Always use the project's virtual environment for all Python operations.

1. **Set up development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On macOS/Linux
   ./venv/bin/python -m pip install -r requirements.txt
   ```

2. **Verify project setup**:
   ```bash
   ./venv/bin/python tests/verify_project.py
   ```

3. **Run tests before making changes**:
   ```bash
   ./venv/bin/python tests/run_all_tests.py
   ```

**Virtual Environment Rules:**
- Always use `./venv/bin/python` instead of bare `python`
- Use `./venv/bin/python -m pip` instead of bare `pip`
- Never use system Python or global packages
- Activate environment for interactive sessions: `source venv/bin/activate`

4. **Follow code style guidelines**:
   - Use type hints for function parameters and return values
   - Include comprehensive docstrings for all public functions
   - Follow PEP 8 style guidelines
   - Add appropriate error handling and logging
   - Maintain test coverage above 90%

### Adding New Features

1. **New Analytics**: Add methods to `SecurityAnalytics` class in `analytics.py`
2. **New Charts**: Add chart types to `ChartGenerator` class in `visualizations.py`
3. **New Data Sources**: Extend `DataLoader` for different formats in `data_loader.py`
4. **New Visualizations**: Update `ReportBuilder` templates in `report_builder.py`
5. **New Data Processing**: Extend `DataProcessor` for additional cleaning/normalization in `data_processor.py`

### Testing Requirements

**Current Test Status**: Many existing tests need updates to match the current API.

**For New Development:**
- Test core functionality with real data: `./venv/bin/python generate_prowler_scan_insights.py`
- Write new tests that match current API interfaces
- Focus on integration testing with actual Prowler CSV files
- Update existing tests when modifying related functionality

**Test Categories to Focus On:**
- Integration tests with real CSV data in `tests/test_integration_*.py`
- Performance testing with large datasets in `tests/test_performance.py`
- HTML output validation in `tests/test_validation_*.py`
- New unit tests should match current module APIs

### Code Quality Standards

- Use type hints for function parameters and return values
- Include comprehensive docstrings for all public functions
- Follow PEP 8 style guidelines
- Add appropriate error handling and logging
- Maintain test coverage above 90%
- Update documentation for API changes
- Consider performance impact for large datasets
- Remove emojis from all documentation and code comments
- Follow accessibility guidelines for documentation
- Use clear, descriptive text instead of symbols or emojis
- Ensure documentation is screen-reader friendly

### AWS-Specific Development

**Current Scope**: This tool is designed and tested specifically for AWS Prowler scans.

**For AWS-related contributions:**
- Test with real AWS Prowler CSV output files
- Ensure compatibility with standard AWS account structures
- Validate against AWS service naming conventions
- Consider AWS-specific security finding patterns

**Future Multi-Cloud Support:**
- When adding support for other cloud providers (Azure, GCP)
- Ensure backward compatibility with existing AWS functionality
- Add provider-specific data processing logic
- Update documentation to reflect multi-cloud capabilities

### Development Workflow

1. **Create feature branch**: Work on new features in separate branches
2. **Write tests first**: Follow TDD approach where possible
3. **Run test suite**: Ensure all tests pass before committing
4. **Update documentation**: Keep README.md and SCAN-INSIGHTS-DASHBOARD.md current
5. **Performance testing**: Test with realistic dataset sizes
6. **Code review**: Have changes reviewed before merging
