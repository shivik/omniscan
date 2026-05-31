"""SARIF is the lingua franca: native output -> SARIF 2.1.0 -> internal Finding.

This package is the *only* place native scanner output becomes a Finding. No
adapter writes the findings DB directly, and no second normalization format exists.
"""
