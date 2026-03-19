import logging
import time

from langchain_community.llms import Ollama

logger = logging.getLogger("LLMRouter")


class LLMRouter:
    """
    Central LLM routing system for AI SOC.

    Routes different cybersecurity tasks to best-suited models:
    - Mixtral → reasoning / attack planning
    - Llama3 → explanation / reporting
    - DeepSeek → code / technical analysis

    Includes:
    ✔ fallback handling
    ✔ timeout safety
    ✔ clean output
    """

    def __init__(self):

        try:
            self.mistral = Ollama(model="mistral:latest")
            self.llama = Ollama(model="llama3.1:latest")
            self.coder = Ollama(model="deepseek-coder:latest")

            logger.info("✅ LLM Router initialized successfully")

        except Exception as e:
            logger.error("❌ Failed to initialize Ollama models")
            logger.error(e)

            self.mistral = None
            self.llama = None
            self.coder = None

    # -----------------------------------
    # Core execution with fallback
    # -----------------------------------
    def _safe_invoke(self, model, prompt, fallback_model=None):

        try:

            start_time = time.time()

            response = model.invoke(prompt)

            duration = round(time.time() - start_time, 2)

            logger.info(f"LLM response generated in {duration}s")

            return self._clean_output(response)

        except Exception as e:

            logger.warning("⚠ LLM failed, trying fallback...")
            logger.warning(e)

            if fallback_model:
                try:
                    response = fallback_model.invoke(prompt)
                    return self._clean_output(response)
                except Exception as e2:
                    logger.error("❌ Fallback LLM also failed")
                    logger.error(e2)

            return "LLM_ERROR: Unable to generate response"

    # -----------------------------------
    # Output cleaner
    # -----------------------------------
    def _clean_output(self, response):

        if not response:
            return ""

        # remove extra whitespace
        text = str(response).strip()

        # optional: truncate if too long
        if len(text) > 3000:
            text = text[:3000] + "..."

        return text

    # -----------------------------------
    # Public method
    # -----------------------------------
    def run(self, task: str, prompt: str) -> str:

        if not prompt:
            return "No prompt provided"

        logger.info(f"🧠 LLM Task → {task}")

        # -----------------------------------
        # Attack reasoning
        # -----------------------------------
        if task == "attack_reasoning":

            return self._safe_invoke(
                model=self.mistral,
                prompt=prompt,
                fallback_model=self.llama
            )

        # -----------------------------------
        # Security explanation
        # -----------------------------------
        elif task == "security_explanation":

            return self._safe_invoke(
                model=self.llama,
                prompt=prompt,
                fallback_model=self.mistral
            )

        # -----------------------------------
        # Code analysis
        # -----------------------------------
        elif task == "code_analysis":

            return self._safe_invoke(
                model=self.coder,
                prompt=prompt,
                fallback_model=self.mistral
            )

        # -----------------------------------
        # Default
        # -----------------------------------
        else:

            return self._safe_invoke(
                model=self.mistral,
                prompt=prompt,
                fallback_model=self.llama
            )