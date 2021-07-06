#include "Compression.h"
#include "MatchersImpl.h"
#include "utils/Distribution.h"

template<typename T>
CompressionDataPointsFilter<T>::CompressionDataPointsFilter(const Parameters& params) :
		PointMatcher<T>::DataPointsFilter("CompressionDataPointsFilter", CompressionDataPointsFilter::availableParameters(), params),
		knn(Parametrizable::get<unsigned>("knn")),
		maxDist(Parametrizable::get<T>("maxDist")),
		epsilon(Parametrizable::get<T>("epsilon")),
		initialVariance(Parametrizable::get<T>("initialVariance")),
		maxDeviation(Parametrizable::get<T>("maxDeviation"))
{
}

// Compute
template<typename T>
typename PointMatcher<T>::DataPoints CompressionDataPointsFilter<T>::filter(const typename PM::DataPoints& input)
{
	typename PM::DataPoints output(input);
	inPlaceFilter(output);
	return output;
}

// In-place filter
template<typename T>
void CompressionDataPointsFilter<T>::inPlaceFilter(typename PM::DataPoints& cloud)
{
	unsigned nbDim = cloud.getEuclideanDim();

	std::vector<Distribution<T>> distributions;
	distributions.reserve(cloud.getNbPoints());
	if(!cloud.descriptorExists("covariance") || !cloud.descriptorExists("weightSum") || !cloud.descriptorExists("nbPoints"))
	{
		for(unsigned i = 0; i < cloud.getNbPoints(); ++i)
		{
			distributions.emplace_back(cloud.features.col(i).topRows(nbDim), initialVariance * PM::Matrix::Identity(nbDim, nbDim));
		}
	}
	else
	{
		const auto& covarianceVectors = cloud.getDescriptorViewByName("covariance");
		const auto& weightSumVectors = cloud.getDescriptorViewByName("weightSum");
		for(unsigned i = 0; i < cloud.getNbPoints(); ++i)
		{
			typename PM::Matrix covariance = PM::Matrix::Zero(nbDim, nbDim);
			typename PM::Matrix weightSum = PM::Matrix::Zero(nbDim, nbDim);
			for(unsigned j = 0; j < nbDim; ++j)
			{
				covariance.col(j) = covarianceVectors.block(j * nbDim, i, nbDim, 1);
				weightSum.col(j) = weightSumVectors.block(j * nbDim, i, nbDim, 1);
			}
			distributions.emplace_back(Distribution<T>(cloud.features.col(i).topRows(nbDim), covariance, weightSum));
		}
	}

	if(!cloud.descriptorExists("covariance"))
	{
		cloud.addDescriptor("covariance", PM::Matrix::Zero(std::pow(nbDim, 2), cloud.getNbPoints()));
	}
	if(!cloud.descriptorExists("weightSum"))
	{
		cloud.addDescriptor("weightSum", PM::Matrix::Zero(std::pow(nbDim, 2), cloud.getNbPoints()));
	}
	if(!cloud.descriptorExists("nbPoints"))
	{
		cloud.addDescriptor("nbPoints", PM::Matrix::Ones(1, cloud.getNbPoints()));
	}

	Parameters params;
	params["knn"] = PointMatcherSupport::toParam(knn);
	params["maxDist"] = PointMatcherSupport::toParam(maxDist);
	params["epsilon"] = PointMatcherSupport::toParam(epsilon);
	typename MatchersImpl<T>::KDTreeMatcher matcher(params);

	int currentNbPoints = cloud.getNbPoints();
	typename PM::DataPoints tempCloud;
	while(tempCloud.getNbPoints() != cloud.getNbPoints())
	{
		tempCloud = cloud;
		Eigen::Matrix<bool, 1, Eigen::Dynamic> masks = Eigen::Matrix<bool, 1, Eigen::Dynamic>::Constant(1, tempCloud.getNbPoints(), true);

		matcher.init(tempCloud);
		typename PM::Matches matches(typename PM::Matches::Dists(knn, tempCloud.getNbPoints()), typename PM::Matches::Ids(knn, tempCloud.getNbPoints()));
		matches = matcher.findClosests(tempCloud);

		for(unsigned i = 0; i < tempCloud.getNbPoints(); ++i)
		{
			if(!masks(0, i))
			{
				continue;
			}

			Distribution<T> neighborhoodDistribution = distributions[matches.ids(0, i)];
			for(unsigned j = 1; j < knn; ++j)
			{
				if(!masks(0, matches.ids(j, i)))
				{
					continue;
				}
				neighborhoodDistribution = neighborhoodDistribution.combine(distributions[matches.ids(j, i)]);
			}
			typename PM::Vector delta = neighborhoodDistribution.getMean() - tempCloud.features.col(i).topRows(nbDim);
			T mahalanobisDistance = std::sqrt(delta.transpose() * distributions[i].getCovariance() * delta);

			if(mahalanobisDistance <= maxDeviation)
			{
				tempCloud.features.col(i).topRows(nbDim) = neighborhoodDistribution.getMean();
				distributions[i] = neighborhoodDistribution;
				for(unsigned j = 0; j < nbDim; ++j)
				{
					tempCloud.getDescriptorViewByName("covariance").block(j * nbDim, i, nbDim, 1) = neighborhoodDistribution.getCovariance().col(j);
					tempCloud.getDescriptorViewByName("weightSum").block(j * nbDim, i, nbDim, 1) = neighborhoodDistribution.getWeightSum().col(j);
				}
				for(unsigned j = 1; j < knn; ++j)
				{
					if(masks(0, matches.ids(j, i)))
					{
						tempCloud.getDescriptorViewByName("nbPoints")(0, i) += tempCloud.getDescriptorViewByName("nbPoints")(0, matches.ids(j, i));
						masks(0, matches.ids(j, i)) = false;
						--currentNbPoints;
					}
				}
			}
		}

		cloud.conservativeResize(currentNbPoints);
		unsigned addedElements = 0;
		for(unsigned i = 0; i < tempCloud.getNbPoints(); ++i)
		{
			if(masks(0, i))
			{
				cloud.setColFrom(addedElements++, tempCloud, i);
			}
			else
			{
				distributions.erase(distributions.begin() + addedElements);
			}
		}
	}
}

template
struct CompressionDataPointsFilter<float>;
template
struct CompressionDataPointsFilter<double>;