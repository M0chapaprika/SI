document.addEventListener('DOMContentLoaded', () => {
    // 1. Obtener elementos del DOM
    const btnReveal = document.getElementById('btnReveal');
    const cardNumberDisplay = document.getElementById('cardNumberDisplay');
    const cardExpiryDisplay = document.getElementById('cardExpiry');
    
    // Verificamos que los elementos existan antes de ejecutar nada
    if (!btnReveal || !cardNumberDisplay || !cardExpiryDisplay) return;

    // 2. Guardamos los valores originales "censurados"
    // Estos vienen de los atributos data-last-four y data-expiry del HTML
    const originalLast4 = cardNumberDisplay.getAttribute('data-last-four') || "0000";
    const originalExpiry = cardExpiryDisplay.getAttribute('data-expiry') || "**/**";
    
    let isRevealed = false;

    btnReveal.addEventListener('click', async () => {
        if (!isRevealed) {
            // ============================
            // CASO: MOSTRAR DATOS
            // ============================
            const originalBtnText = btnReveal.innerHTML;
            
            try {
                // UI: Cambiar botón a cargando
                btnReveal.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Desencriptando...';
                btnReveal.disabled = true;

                // PETICIÓN AL SERVIDOR
                const response = await fetch('/api/obtener-tarjeta', {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json' }
                });

                // --- MANEJO DE ERRORES DE SESIÓN (SOLUCIÓN AL "<!DOCTYPE html>") ---
                const contentType = response.headers.get("content-type");
                if (contentType && contentType.includes("text/html")) {
                    // Si el servidor devuelve HTML en vez de JSON, es porque la sesión expiró
                    // y te redirigió al Login.
                    alert("Tu sesión ha expirado. Vamos a recargar para que inicies sesión.");
                    window.location.reload(); 
                    return;
                }
                // ------------------------------------------------------------------

                // Si no es HTML, intentamos leer el JSON
                const data = await response.json();

                if (response.ok && data.success) {
                    // ÉXITO: Mostramos los datos reales
                    
                    // 1. Formatear Tarjeta (grupos de 4)
                    // Si viene vacía, ponemos ceros
                    const rawNum = data.numero || "0000000000000000"; 
                    const formattedNumber = rawNum.match(/.{1,4}/g).join(' ');
                    cardNumberDisplay.innerText = formattedNumber;

                    // 2. Formatear Vencimiento
                    cardExpiryDisplay.innerText = data.vencimiento;

                    // 3. Actualizar estado y botón
                    isRevealed = true;
                    btnReveal.innerHTML = '<i class="fas fa-eye-slash"></i> Ocultar Datos';
                    btnReveal.style.color = '#c0392b'; // Rojo de advertencia
                    
                } else {
                    // ERROR CONTROLADO (ej: no hay tarjeta asociada)
                    throw new Error(data.error || 'Error desconocido del servidor');
                }

            } catch (error) {
                console.error("Error en petición:", error);
                alert('No se pudieron obtener los datos: ' + error.message);
                
                // Restaurar botón original
                btnReveal.innerHTML = originalBtnText;
                isRevealed = false;
            } finally {
                btnReveal.disabled = false;
            }

        } else {
            // ============================
            // CASO: OCULTAR DATOS
            // ============================
            
            // 1. Restaurar el número con asteriscos
            cardNumberDisplay.innerHTML = `<span>****</span> <span>****</span> <span>****</span> ${originalLast4}`;
            
            // 2. Restaurar la fecha oculta
            cardExpiryDisplay.innerText = originalExpiry;
            
            // 3. Resetear el botón
            isRevealed = false;
            btnReveal.innerHTML = '<i class="fas fa-eye"></i> Mostrar Datos';
            btnReveal.style.color = ''; // Volver al color original (CSS)
        }
    });
});