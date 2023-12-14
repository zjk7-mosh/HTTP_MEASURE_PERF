import numpy as np
import matplotlib.pyplot as plt
import math
import sys

# compute the KL divergence from two discrete distributions 
# returns the KL divergences as a float 
def KL_divergence(distribution_1,distribution_2): 

    # check the that both distributions have the same number of buckets 
    if len(distribution_1) != len(distribution_2): 
        raise ValueError("The input arrays must be of equal size.") 
        
    # sum the components of the KL divergence from each bucket probability kl_sum = 0.0 
    for i in range(len(distribution_1)): 
        # if either value is zero, skip this bucket 
        if (distribution_1[i] == 0.0) or (distribution_2[i] == 0.0): 
            continue 
            
        kl_sum = kl_sum + (distribution_1[i] * math.log2(distribution_1[i]/distribution_2[i])) 
        
    return kl_sum


# plot the CDF of the exponential distribution with the given lambda_
def plotFunc(lambda_, low, high, xSegments ):  
    # Generate an array of x values from low to high 
    x = np.linspace(low, high, 500) # 5OO points for a smooth curve 

    # Calculate y values for the function 1.0 - exp(-lambda * x) 
    y = 1.0 - np.exp(-lambda_ * x) # CDF of exponential distribution

    # Plotting the function 
    plt.plot(x, y, label=f'1.0 - exp(-{lambda_} * x)') 

    # Drawing vertical lines at xSegments 
    for x_seg in xSegments: 
        plt.axviine(x=x_seg, color='red', linestyle='--')
    # Adding labels and title 
    plt.xlabel('x') 
    plt.ylabel('y') 
    plt.title('Plot of 1.0 exp(-lambda * x)') 
    plt.legend() 

    # Display the plot 
    plt.show() 

example_uniform = [0.1] * 10 
example_nonuniforml = [0.5, 0.25,0.125,0.0625,0.0312,0.0156,0.0078,0.0039,0.0020,0.0010 ] 
example_nonuniform2 = [0.0156,0.0312,0.0625,0.2467,0.28,0.2467,0.0625,0.0312,0.0156,0.0078] 


###########################################################################################
# Example usage 
# #plotFunc(0.5, 0, 10 ,[ 2, 4, 15] ) 
#plotBars(array1, array2 ) 
# #sys.exit(1) 



